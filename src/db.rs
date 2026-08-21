//! The analysis database: what you worked out, kept between sessions.
//!
//! Everything else in knife is derived from the bytes and can be recomputed at
//! any time. This file holds the opposite: the facts only a person can supply,
//! a function's real name and a note about what it does. That is the difference
//! between reading a binary once and working on one over days.
//!
//! Three decisions shape the format:
//!
//! **Keyed by content, not by path.** The database is found by the file's
//! SHA-256, so renaming or moving the target keeps the work, and pointing knife
//! at a different build never silently applies the wrong names.
//!
//! **Addresses are stored base-relative.** What you see and type is the virtual
//! address, but what is written down is the offset from the image base, so a
//! database stays correct if the image is ever rebased.
//!
//! **The file is meant to be read.** Addresses are hex strings and entries are
//! a flat list, so a database can be diffed, hand-edited, and sent to someone
//! else without any tooling on their end.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// First `n` characters of `s`, without ever splitting a UTF-8 code point.
fn truncated(s: &str, n: usize) -> &str {
    let mut end = s.len().min(n);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// One stored fact, as it appears on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    /// Base-relative address, written as hex so the file reads like the tool.
    at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FieldEntry {
    #[serde(rename = "type")]
    type_name: String,
    /// Signed byte offset, written as `0x18` or `-0x8`.
    offset: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BindingEntry {
    /// Base-relative function entry address.
    function: String,
    /// Stable IR base identity (`rcx`, `var_8`, ...).
    base: String,
    #[serde(rename = "type")]
    type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VariableEntry {
    /// Base-relative function entry address.
    function: String,
    /// Stable recovered identity (`rcx`, `arg_8`, `var_20`, ...).
    base: String,
    /// Analyst-facing source-style name.
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrototypeEntry {
    /// Base-relative function entry address.
    function: String,
    returns: String,
    #[serde(default)]
    params: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatchEntry {
    /// File offset, written in hex for hand inspection.
    offset: String,
    /// Original bytes expected at this offset.
    original: String,
    /// Staged replacement bytes.
    bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TypeLibrary {
    schema: u32,
    #[serde(default)]
    types: Vec<LibraryType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryType {
    name: String,
    #[serde(default)]
    fields: Vec<LibraryField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryField {
    offset: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    pub types: usize,
    pub fields: usize,
}

/// An analyst-supplied function prototype. Parameter identities remain the
/// recovered ABI bases (`rcx`, `rdi`, `arg_8`, ...); this stores their ordered
/// C types without inventing source-level names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPrototype {
    pub returns: String,
    pub params: Vec<String>,
}

/// One analyst-defined structure member. Older databases store only `name`;
/// `data_type` is optional so those layouts remain valid and useful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserField {
    pub name: String,
    pub data_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchByte {
    pub original: u8,
    pub replacement: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchRun {
    pub offset: u64,
    pub original: Vec<u8>,
    pub bytes: Vec<u8>,
}

impl fmt::Display for UserField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if let Some(ty) = &self.data_type {
            write!(f, ": {ty}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OnDisk {
    /// Identity of the binary these annotations belong to.
    sha256: String,
    /// Last path the target was seen at. Informational: lookup is by hash.
    #[serde(default)]
    file: String,
    #[serde(default)]
    entries: Vec<Entry>,
    #[serde(default)]
    fields: Vec<FieldEntry>,
    #[serde(default)]
    bindings: Vec<BindingEntry>,
    #[serde(default)]
    variables: Vec<VariableEntry>,
    #[serde(default)]
    prototypes: Vec<PrototypeEntry>,
    #[serde(default)]
    patches: Vec<PatchEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct Db {
    pub sha256: String,
    pub file: String,
    /// Base-relative address -> the name you gave it.
    pub names: BTreeMap<u64, String>,
    /// Base-relative address -> your note.
    pub notes: BTreeMap<u64, String>,
    /// User type -> signed byte offset -> field definition.
    pub fields: BTreeMap<String, BTreeMap<i64, UserField>>,
    /// (base-relative function entry, IR base identity) -> user type.
    pub bindings: BTreeMap<(u64, String), String>,
    /// (base-relative function entry, stable IR identity) -> display alias.
    pub variables: BTreeMap<(u64, String), String>,
    /// Base-relative function entry -> exact analyst-supplied prototype.
    pub prototypes: BTreeMap<u64, UserPrototype>,
    /// Original file offset -> staged replacement with its expected byte.
    pub patches: BTreeMap<u64, PatchByte>,
    path: Option<PathBuf>,
}

impl Db {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
            && self.notes.is_empty()
            && self.fields.is_empty()
            && self.bindings.is_empty()
            && self.variables.is_empty()
            && self.prototypes.is_empty()
            && self.patches.is_empty()
    }

    pub fn len(&self) -> usize {
        self.names.len()
            + self.notes.len()
            + self.fields.values().map(BTreeMap::len).sum::<usize>()
            + self.bindings.len()
            + self.variables.len()
            + self.prototypes.len()
            + self.patches.len()
    }

    /// Where this database lives, once it has a home.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Load the database for a binary, or start an empty one.
    ///
    /// A missing file is not an error: the first annotation creates it. A
    /// corrupt one is an error, because silently discarding somebody's notes is
    /// worse than refusing to run.
    pub fn load(sha256: &str, file: &str, explicit: Option<&str>) -> Result<Db> {
        let path = match explicit {
            Some(p) => PathBuf::from(p),
            None => store_dir().join(format!("{sha256}.json")),
        };

        let mut db = Db {
            sha256: sha256.to_string(),
            file: file.to_string(),
            path: Some(path.clone()),
            ..Default::default()
        };

        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(db);
        };
        let disk: OnDisk = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a valid knife database", path.display()))?;

        // A database named for one binary but carrying another's hash means the
        // file was copied by hand; say so rather than applying the wrong names.
        if !disk.sha256.is_empty() && disk.sha256 != sha256 {
            anyhow::bail!(
                "{} belongs to a different binary (sha256 {}…, this file is {}…)",
                path.display(),
                truncated(&disk.sha256, 12),
                truncated(sha256, 12),
            );
        }

        for e in disk.entries {
            let Some(at) = parse_hex(&e.at) else { continue };
            if !e.name.is_empty() {
                db.names.insert(at, e.name);
            }
            if !e.note.is_empty() {
                db.notes.insert(at, e.note);
            }
        }
        for field in disk.fields {
            let Some(offset) = parse_signed_hex(&field.offset) else {
                continue;
            };
            if valid_identifier(&field.type_name)
                && valid_identifier(&field.name)
                && field.data_type.as_deref().is_none_or(valid_c_type)
            {
                db.fields.entry(field.type_name).or_default().insert(
                    offset,
                    UserField {
                        name: field.name,
                        data_type: field.data_type.map(|ty| normalize_c_type(&ty)),
                    },
                );
            }
        }
        for binding in disk.bindings {
            let Some(function) = parse_hex(&binding.function) else {
                continue;
            };
            if valid_identifier(&binding.type_name) && valid_base(&binding.base) {
                db.bindings
                    .insert((function, binding.base), binding.type_name);
            }
        }
        for variable in disk.variables {
            let Some(function) = parse_hex(&variable.function) else {
                continue;
            };
            if valid_base(&variable.base) && valid_identifier(&variable.name) {
                db.variables
                    .insert((function, variable.base), variable.name);
            }
        }
        for prototype in disk.prototypes {
            let Some(function) = parse_hex(&prototype.function) else {
                continue;
            };
            if valid_c_type(&prototype.returns)
                && prototype.params.iter().all(|param| valid_c_type(param))
            {
                db.prototypes.insert(
                    function,
                    UserPrototype {
                        returns: normalize_c_type(&prototype.returns),
                        params: prototype
                            .params
                            .iter()
                            .map(|param| normalize_c_type(param))
                            .collect(),
                    },
                );
            }
        }
        for patch in disk.patches {
            let offset = parse_hex(&patch.offset)
                .with_context(|| format!("patch has invalid offset '{}'", patch.offset))?;
            let original = decode_hex_bytes(&patch.original)
                .with_context(|| format!("patch at {offset:#x} has invalid original bytes"))?;
            let replacement = decode_hex_bytes(&patch.bytes)
                .with_context(|| format!("patch at {offset:#x} has invalid replacement bytes"))?;
            if original.is_empty() || original.len() != replacement.len() {
                anyhow::bail!(
                    "patch at {offset:#x} must have equal non-empty original and replacement bytes"
                )
            }
            for (index, (&original, &replacement)) in original.iter().zip(&replacement).enumerate()
            {
                let at = offset
                    .checked_add(index as u64)
                    .context("patch offset overflows the file address space")?;
                if db
                    .patches
                    .insert(
                        at,
                        PatchByte {
                            original,
                            replacement,
                        },
                    )
                    .is_some()
                {
                    anyhow::bail!("overlapping patch byte at file offset {at:#x}")
                }
            }
        }
        Ok(db)
    }

    pub fn set_name(&mut self, at: u64, name: &str) {
        self.names.insert(at, name.to_string());
    }

    pub fn set_note(&mut self, at: u64, note: &str) {
        self.notes.insert(at, note.to_string());
    }

    #[cfg(test)]
    pub fn set_field(&mut self, type_name: &str, offset: i64, name: &str) -> Result<()> {
        self.set_typed_field(type_name, offset, name, None)
    }

    pub fn set_typed_field(
        &mut self,
        type_name: &str,
        offset: i64,
        name: &str,
        data_type: Option<&str>,
    ) -> Result<()> {
        validate_identifier(type_name, "type name")?;
        validate_identifier(name, "field name")?;
        if let Some(ty) = data_type {
            validate_c_type(ty, "field type")?;
        }
        self.fields
            .entry(type_name.to_string())
            .or_default()
            .insert(
                offset,
                UserField {
                    name: name.to_string(),
                    data_type: data_type.map(normalize_c_type),
                },
            );
        Ok(())
    }

    pub fn clear_field(&mut self, type_name: &str, offset: i64) -> Option<UserField> {
        let fields = self.fields.get_mut(type_name)?;
        let old = fields.remove(&offset);
        if fields.is_empty() {
            self.fields.remove(type_name);
        }
        old
    }

    pub fn bind_type(&mut self, function: u64, base: &str, type_name: &str) -> Result<()> {
        validate_base(base)?;
        validate_identifier(type_name, "type name")?;
        self.bindings
            .insert((function, base.to_string()), type_name.to_string());
        Ok(())
    }

    pub fn clear_binding(&mut self, function: u64, base: &str) -> Option<String> {
        self.bindings.remove(&(function, base.to_string()))
    }

    pub fn bound_type(&self, function: u64, base: &str) -> Option<&str> {
        self.bindings
            .get(&(function, base.to_string()))
            .map(String::as_str)
    }

    pub fn set_variable(&mut self, function: u64, base: &str, name: &str) -> Result<()> {
        validate_base(base)?;
        validate_identifier(name, "variable name")?;
        if let Some(((_, other_base), _)) =
            self.variables
                .iter()
                .find(|((owner, other_base), old_name)| {
                    *owner == function && other_base != base && old_name.as_str() == name
                })
        {
            anyhow::bail!("variable name '{name}' is already used for {other_base}")
        }
        self.variables
            .insert((function, base.to_string()), name.to_string());
        Ok(())
    }

    pub fn clear_variable(&mut self, function: u64, base: &str) -> Option<String> {
        self.variables.remove(&(function, base.to_string()))
    }

    pub fn variable_name(&self, function: u64, base: &str) -> Option<&str> {
        self.variables
            .get(&(function, base.to_string()))
            .map(String::as_str)
    }

    pub fn field_name(&self, function: u64, base: &str, offset: i64) -> Option<&str> {
        let type_name = self.bound_type(function, base)?;
        self.fields
            .get(type_name)?
            .get(&offset)
            .map(|field| field.name.as_str())
    }

    pub fn set_prototype(&mut self, function: u64, returns: &str, params: &[String]) -> Result<()> {
        validate_c_type(returns, "return type")?;
        for param in params {
            validate_c_type(param, "parameter type")?;
        }
        self.prototypes.insert(
            function,
            UserPrototype {
                returns: normalize_c_type(returns),
                params: params.iter().map(|param| normalize_c_type(param)).collect(),
            },
        );
        Ok(())
    }

    pub fn clear_prototype(&mut self, function: u64) -> Option<UserPrototype> {
        self.prototypes.remove(&function)
    }

    pub fn prototype(&self, function: u64) -> Option<&UserPrototype> {
        self.prototypes.get(&function)
    }

    pub fn stage_patch(&mut self, source: &[u8], offset: u64, bytes: &[u8]) -> Result<usize> {
        if bytes.is_empty() {
            anyhow::bail!("patch bytes cannot be empty")
        }
        let start = usize::try_from(offset).context("patch offset is too large")?;
        let end = start
            .checked_add(bytes.len())
            .context("patch range overflows")?;
        if end > source.len() {
            anyhow::bail!(
                "patch range {offset:#x}..{:#x} exceeds the {}-byte file",
                offset + bytes.len() as u64,
                source.len()
            )
        }
        let mut next = self.patches.clone();
        for (index, &replacement) in bytes.iter().enumerate() {
            let at = offset + index as u64;
            let original = next
                .get(&at)
                .map_or(source[start + index], |patch| patch.original);
            if replacement == original {
                next.remove(&at);
            } else {
                next.insert(
                    at,
                    PatchByte {
                        original,
                        replacement,
                    },
                );
            }
        }
        self.patches = next;
        Ok(bytes.len())
    }

    pub fn clear_patch_range(&mut self, offset: u64, len: usize) -> Vec<(u64, u8)> {
        (0..len)
            .filter_map(|index| {
                let at = offset.checked_add(index as u64)?;
                self.patches.remove(&at).map(|patch| (at, patch.original))
            })
            .collect()
    }

    pub fn clear_patch_run_at(&mut self, offset: u64) -> Vec<(u64, u8)> {
        let Some(run) = self
            .patch_runs()
            .into_iter()
            .find(|run| offset >= run.offset && offset < run.offset + run.bytes.len() as u64)
        else {
            return Vec::new();
        };
        self.clear_patch_range(run.offset, run.bytes.len())
    }

    /// Apply the staged edits to a copy of the file.
    ///
    /// Takes the bytes by value and edits them in place. Copying first would
    /// double the resident cost of every analysed image, and the callers all
    /// hand over an image they are done with; a target with no staged patches
    /// then costs nothing at all.
    pub fn apply_patches(&self, original: Vec<u8>) -> Result<Vec<u8>> {
        let mut patched = original;
        for (&offset, patch) in &self.patches {
            let index = usize::try_from(offset).context("patch offset is too large")?;
            let Some(byte) = patched.get_mut(index) else {
                anyhow::bail!("patch at {offset:#x} exceeds the current file")
            };
            if *byte != patch.original {
                anyhow::bail!(
                    "patch at {offset:#x} expects {:02x}, but the file contains {:02x}",
                    patch.original,
                    *byte
                )
            }
            *byte = patch.replacement;
        }
        Ok(patched)
    }

    pub fn patch_runs(&self) -> Vec<PatchRun> {
        let mut runs = Vec::new();
        let mut current: Option<PatchRun> = None;
        for (&offset, patch) in &self.patches {
            let contiguous = current
                .as_ref()
                .is_some_and(|run| run.offset + run.bytes.len() as u64 == offset);
            if !contiguous {
                if let Some(run) = current.take() {
                    runs.push(run);
                }
                current = Some(PatchRun {
                    offset,
                    original: Vec::new(),
                    bytes: Vec::new(),
                });
            }
            let run = current.as_mut().expect("created above");
            run.original.push(patch.original);
            run.bytes.push(patch.replacement);
        }
        if let Some(run) = current {
            runs.push(run);
        }
        runs
    }

    /// Export portable structure layouts only. Function bindings, variable
    /// aliases, and prototypes are address-scoped facts and deliberately never
    /// leave the binary database through this format.
    pub fn export_type_library(&self, path: &Path) -> Result<ImportSummary> {
        let library = TypeLibrary {
            schema: 1,
            types: self
                .fields
                .iter()
                .map(|(name, fields)| LibraryType {
                    name: name.clone(),
                    fields: fields
                        .iter()
                        .map(|(&offset, field)| LibraryField {
                            offset: format_signed_hex(offset),
                            name: field.name.clone(),
                            data_type: field.data_type.clone(),
                        })
                        .collect(),
                })
                .collect(),
        };
        let summary = ImportSummary {
            types: library.types.len(),
            fields: library.types.iter().map(|ty| ty.fields.len()).sum(),
        };
        let text = serde_json::to_string_pretty(&library)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let tmp = path.with_extension("typelib.tmp");
        std::fs::write(&tmp, text).with_context(|| format!("cannot write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(summary)
    }

    /// Import a complete library transactionally. In merge mode, an existing
    /// offset may be repeated only with the same name. In replace mode, every
    /// named incoming layout replaces that type as a unit; unrelated types are
    /// preserved.
    pub fn import_type_library(&mut self, path: &Path, replace: bool) -> Result<ImportSummary> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let library: TypeLibrary = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a valid Knife type library", path.display()))?;
        if library.schema != 1 {
            anyhow::bail!(
                "unsupported type-library schema {} (expected 1)",
                library.schema
            )
        }

        let mut incoming: BTreeMap<String, BTreeMap<i64, UserField>> = BTreeMap::new();
        for ty in library.types {
            validate_identifier(&ty.name, "type name")?;
            if incoming.contains_key(&ty.name) {
                anyhow::bail!("duplicate type '{}' in {}", ty.name, path.display())
            }
            let mut fields = BTreeMap::new();
            for field in ty.fields {
                validate_identifier(&field.name, "field name")?;
                if let Some(ty) = &field.data_type {
                    validate_c_type(ty, "field type")?;
                }
                let offset = parse_signed_hex(&field.offset).with_context(|| {
                    format!(
                        "field {}.{} has invalid signed offset '{}'",
                        ty.name, field.name, field.offset
                    )
                })?;
                let definition = UserField {
                    name: field.name,
                    data_type: field.data_type.map(|ty| normalize_c_type(&ty)),
                };
                if fields.insert(offset, definition).is_some() {
                    anyhow::bail!("duplicate offset {offset:+#x} in type '{}'", ty.name)
                }
            }
            incoming.insert(ty.name, fields);
        }

        if !replace {
            for (type_name, fields) in &incoming {
                if let Some(existing) = self.fields.get(type_name) {
                    for (offset, field) in fields {
                        if let Some(old) = existing.get(offset) {
                            if old != field {
                                anyhow::bail!(
                                    "conflict at {type_name}{offset:+#x}: database has '{}', library has '{}' (use --replace)",
                                    describe_field(old), describe_field(field)
                                )
                            }
                        }
                    }
                }
            }
        }

        let summary = ImportSummary {
            types: incoming.len(),
            fields: incoming.values().map(BTreeMap::len).sum(),
        };
        for (type_name, fields) in incoming {
            if replace {
                self.fields.insert(type_name, fields);
            } else {
                self.fields.entry(type_name).or_default().extend(fields);
            }
        }
        Ok(summary)
    }

    /// Remove whatever is stored at an address. Returns what was there.
    pub fn clear(&mut self, at: u64) -> (Option<String>, Option<String>) {
        (self.names.remove(&at), self.notes.remove(&at))
    }

    /// Write the database out, creating its directory if needed.
    ///
    /// Writing goes through a temporary file and a rename, so an interrupted
    /// save cannot leave a half-written database where a complete one was.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
        }

        let mut addrs: Vec<u64> = self
            .names
            .keys()
            .chain(self.notes.keys())
            .copied()
            .collect();
        addrs.sort_unstable();
        addrs.dedup();

        let disk = OnDisk {
            sha256: self.sha256.clone(),
            file: self.file.clone(),
            entries: addrs
                .into_iter()
                .map(|at| Entry {
                    at: format!("0x{at:x}"),
                    name: self.names.get(&at).cloned().unwrap_or_default(),
                    note: self.notes.get(&at).cloned().unwrap_or_default(),
                })
                .collect(),
            fields: self
                .fields
                .iter()
                .flat_map(|(type_name, fields)| {
                    fields.iter().map(|(&offset, field)| FieldEntry {
                        type_name: type_name.clone(),
                        offset: format_signed_hex(offset),
                        name: field.name.clone(),
                        data_type: field.data_type.clone(),
                    })
                })
                .collect(),
            bindings: self
                .bindings
                .iter()
                .map(|((function, base), type_name)| BindingEntry {
                    function: format!("0x{function:x}"),
                    base: base.clone(),
                    type_name: type_name.clone(),
                })
                .collect(),
            variables: self
                .variables
                .iter()
                .map(|((function, base), name)| VariableEntry {
                    function: format!("0x{function:x}"),
                    base: base.clone(),
                    name: name.clone(),
                })
                .collect(),
            prototypes: self
                .prototypes
                .iter()
                .map(|(function, prototype)| PrototypeEntry {
                    function: format!("0x{function:x}"),
                    returns: prototype.returns.clone(),
                    params: prototype.params.clone(),
                })
                .collect(),
            patches: self
                .patch_runs()
                .into_iter()
                .map(|patch| PatchEntry {
                    offset: format!("0x{:x}", patch.offset),
                    original: encode_hex_bytes(&patch.original),
                    bytes: encode_hex_bytes(&patch.bytes),
                })
                .collect(),
        };

        let text = serde_json::to_string_pretty(&disk)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).with_context(|| format!("cannot write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
    }
}

/// Where databases live when no path is given.
///
/// A central store is used rather than a file beside the target, because the
/// interesting targets are usually somewhere you cannot write: a system
/// directory, a mounted image, a read-only sample share.
pub fn store_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KNIFE_DB_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    if let Ok(d) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(d).join("knife");
    }
    #[cfg(target_os = "macos")]
    if let Ok(d) = std::env::var("HOME") {
        return PathBuf::from(d).join("Library/Application Support/knife");
    }
    if let Ok(d) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(d).join("knife");
    }
    if let Ok(d) = std::env::var("HOME") {
        return PathBuf::from(d).join(".local/share/knife");
    }
    PathBuf::from(".knife")
}

fn parse_hex(s: &str) -> Option<u64> {
    let t = s.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => t.parse::<u64>().ok(),
    }
}

fn parse_signed_hex(s: &str) -> Option<i64> {
    let text = s.trim();
    if let Some(rest) = text.strip_prefix('-') {
        let magnitude = parse_hex(rest)?;
        i64::try_from(magnitude).ok()?.checked_neg()
    } else {
        i64::try_from(parse_hex(text)?).ok()
    }
}

fn format_signed_hex(offset: i64) -> String {
    if offset < 0 {
        format!("-0x{:x}", offset.unsigned_abs())
    } else {
        format!("0x{offset:x}")
    }
}

pub fn parse_patch_bytes(value: &str) -> Result<Vec<u8>> {
    let mut hex = String::new();
    let mut chars = value.trim().chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'x') {
            chars.next();
            continue;
        }
        if ch == '0' && matches!(chars.peek(), Some('x' | 'X')) {
            chars.next();
            continue;
        }
        if ch.is_ascii_hexdigit() {
            hex.push(ch);
        } else if ch.is_ascii_whitespace() || matches!(ch, ',' | ':' | '_' | '-') {
            continue;
        } else {
            anyhow::bail!("patch bytes contain invalid character '{ch}'")
        }
    }
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        anyhow::bail!("patch bytes must contain a non-empty even number of hex digits")
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16).with_context(|| {
                format!(
                    "invalid patch byte '{}{}'",
                    &hex[index..index + 1],
                    &hex[index + 1..index + 2]
                )
            })
        })
        .collect()
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>> {
    parse_patch_bytes(value)
}

fn encode_hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn describe_field(field: &UserField) -> String {
    match &field.data_type {
        Some(ty) => format!("{}: {ty}", field.name),
        None => field.name.clone(),
    }
}

pub fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn validate_identifier(value: &str, what: &str) -> Result<()> {
    if !valid_identifier(value) {
        anyhow::bail!("{what} must be a C-style identifier")
    }
    Ok(())
}

pub fn valid_base(value: &str) -> bool {
    valid_identifier(value)
}

fn validate_base(value: &str) -> Result<()> {
    if !valid_base(value) {
        anyhow::bail!("base must be a register or local identifier")
    }
    Ok(())
}

pub fn valid_c_type(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch == '_' || ch == '*' || ch.is_ascii_alphanumeric() || ch.is_whitespace())
    {
        return false;
    }
    let words = value.split('*').flat_map(str::split_whitespace);
    let mut saw_word = false;
    for word in words {
        saw_word = true;
        if !valid_identifier(word) {
            return false;
        }
    }
    saw_word
}

fn validate_c_type(value: &str, what: &str) -> Result<()> {
    if !valid_c_type(value) {
        anyhow::bail!("{what} must contain only C type identifiers and pointer stars")
    }
    Ok(())
}

fn normalize_c_type(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("knife-db-test-{tag}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn a_missing_database_is_empty_not_an_error() {
        let p = tmp_path("missing");
        let db = Db::load("abc123", "t.exe", Some(p.to_str().unwrap())).unwrap();
        assert!(db.is_empty());
    }

    #[test]
    fn annotations_survive_a_round_trip() {
        let p = tmp_path("roundtrip");
        let ps = p.to_str().unwrap().to_string();

        let mut db = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        db.set_name(0x1400, "parse_header");
        db.set_note(0x1444, "length is attacker controlled");
        db.save().unwrap();

        let back = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        assert_eq!(
            back.names.get(&0x1400).map(String::as_str),
            Some("parse_header")
        );
        assert_eq!(
            back.notes.get(&0x1444).map(String::as_str),
            Some("length is attacker controlled")
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_database_for_another_binary_is_refused() {
        // Applying one binary's names to another would be worse than useless:
        // it would look like analysis.
        let p = tmp_path("mismatch");
        let ps = p.to_str().unwrap().to_string();

        let mut db = Db::load("aaaaaaaaaaaaaaaa", "a.exe", Some(&ps)).unwrap();
        db.set_name(0x1000, "from_a");
        db.save().unwrap();

        let err = Db::load("bbbbbbbbbbbbbbbb", "b.exe", Some(&ps)).unwrap_err();
        assert!(
            err.to_string().contains("different binary"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn clearing_removes_both_name_and_note() {
        let p = tmp_path("clear");
        let ps = p.to_str().unwrap().to_string();
        let mut db = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        db.set_name(0x2000, "x");
        db.set_note(0x2000, "y");
        let (n, c) = db.clear(0x2000);
        assert_eq!(n.as_deref(), Some("x"));
        assert_eq!(c.as_deref(), Some("y"));
        assert!(db.is_empty());
    }

    #[test]
    fn the_stored_file_is_hex_and_hand_editable() {
        let p = tmp_path("hex");
        let ps = p.to_str().unwrap().to_string();
        let mut db = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        db.set_name(0x401000, "main");
        db.save().unwrap();

        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"0x401000\""), "addresses are hex: {text}");
        assert!(text.contains("\"main\""));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn hand_written_decimal_addresses_still_load() {
        // Somebody will edit this file by hand; accept the obvious alternative.
        let p = tmp_path("decimal");
        std::fs::write(
            &p,
            r#"{"sha256":"abc123","file":"t.exe","entries":[{"at":"4198400","name":"main"}]}"#,
        )
        .unwrap();
        let db = Db::load("abc123", "t.exe", Some(p.to_str().unwrap())).unwrap();
        assert_eq!(db.names.get(&0x401000).map(String::as_str), Some("main"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn user_types_fields_and_bindings_survive_a_round_trip() {
        let p = tmp_path("types");
        let ps = p.to_str().unwrap().to_string();
        let mut db = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        db.set_typed_field("CONTEXT", 0x18, "flags", Some("uint32_t"))
            .unwrap();
        db.set_field("CONTEXT", -8, "header").unwrap();
        db.bind_type(0x1400, "rcx", "CONTEXT").unwrap();
        db.set_variable(0x1400, "rcx", "context").unwrap();
        db.set_prototype(
            0x1400,
            "bool",
            &[
                "CONTEXT *".into(),
                "const uint8_t *".into(),
                "size_t".into(),
            ],
        )
        .unwrap();
        db.save().unwrap();

        let back = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        assert_eq!(back.bound_type(0x1400, "rcx"), Some("CONTEXT"));
        assert_eq!(back.variable_name(0x1400, "rcx"), Some("context"));
        assert_eq!(back.field_name(0x1400, "rcx", 0x18), Some("flags"));
        assert_eq!(
            back.fields["CONTEXT"][&0x18].data_type.as_deref(),
            Some("uint32_t")
        );
        assert_eq!(back.field_name(0x1400, "rcx", -8), Some("header"));
        assert_eq!(
            back.prototype(0x1400),
            Some(&UserPrototype {
                returns: "bool".into(),
                params: vec![
                    "CONTEXT *".into(),
                    "const uint8_t *".into(),
                    "size_t".into()
                ],
            })
        );
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.contains("\"offset\": \"-0x8\""),
            "signed offsets stay readable: {text}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn old_databases_load_with_empty_type_sections() {
        let p = tmp_path("old-schema");
        std::fs::write(
            &p,
            r#"{"sha256":"abc123","entries":[{"at":"0x1000","name":"main"}]}"#,
        )
        .unwrap();
        let db = Db::load("abc123", "t.exe", Some(p.to_str().unwrap())).unwrap();
        assert_eq!(db.names.get(&0x1000).map(String::as_str), Some("main"));
        assert!(db.fields.is_empty() && db.bindings.is_empty() && db.prototypes.is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn old_untyped_field_entries_remain_compatible() {
        let p = tmp_path("old-untyped-fields");
        std::fs::write(
            &p,
            r#"{"sha256":"abc123","fields":[{"type":"CONTEXT","offset":"0x8","name":"length"}]}"#,
        )
        .unwrap();
        let db = Db::load("abc123", "t.exe", Some(p.to_str().unwrap())).unwrap();
        let field = &db.fields["CONTEXT"][&8];
        assert_eq!(field.name, "length");
        assert_eq!(field.data_type, None);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn invalid_type_identifiers_are_rejected() {
        let mut db = Db::default();
        assert!(db.set_field("bad type", 8, "flags").is_err());
        assert!(db.set_field("GOOD", 8, "bad-name").is_err());
        assert!(db
            .set_typed_field("GOOD", 8, "flags", Some("bad-type"))
            .is_err());
        assert!(db.bind_type(0, "rcx+8", "GOOD").is_err());
        assert!(db
            .set_prototype(0, "void); evil(", &["char *".into()])
            .is_err());
        assert!(db.set_prototype(0, "void", &["bad-type".into()]).is_err());
        assert!(db.set_variable(0, "rcx+8", "context").is_err());
        assert!(db.set_variable(0, "rcx", "bad-name").is_err());
        db.set_variable(0, "rcx", "context").unwrap();
        assert!(db.set_variable(0, "rdx", "context").is_err());
    }

    #[test]
    fn portable_type_libraries_round_trip_across_binary_databases() {
        let library = tmp_path("typelib-roundtrip");
        let mut source = Db::default();
        source
            .set_typed_field("CONTEXT", 0x18, "length", Some("size_t"))
            .unwrap();
        source.set_field("CONTEXT", -8, "header").unwrap();
        source.bind_type(0x1000, "rcx", "CONTEXT").unwrap();
        source.set_variable(0x1000, "rcx", "context").unwrap();
        source
            .set_prototype(0x1000, "bool", &["CONTEXT *".into()])
            .unwrap();
        let exported = source.export_type_library(&library).unwrap();
        assert_eq!(
            exported,
            ImportSummary {
                types: 1,
                fields: 2
            }
        );

        let mut destination = Db::default();
        let imported = destination.import_type_library(&library, false).unwrap();
        assert_eq!(imported, exported);
        assert_eq!(
            destination.fields.get("CONTEXT"),
            source.fields.get("CONTEXT")
        );
        assert!(
            destination.bindings.is_empty()
                && destination.variables.is_empty()
                && destination.prototypes.is_empty()
        );
        let text = std::fs::read_to_string(&library).unwrap();
        assert!(
            text.contains("\"schema\": 1")
                && text.contains("\"offset\": \"-0x8\"")
                && text.contains("\"data_type\": \"size_t\"")
        );
        let _ = std::fs::remove_file(library);
    }

    #[test]
    fn type_library_merge_conflicts_are_atomic_and_replace_is_explicit() {
        let library = tmp_path("typelib-conflict");
        std::fs::write(
            &library,
            r#"{"schema":1,"types":[{"name":"CONTEXT","fields":[{"offset":"0x8","name":"new_name"},{"offset":"0x10","name":"flags"}]}]}"#,
        )
        .unwrap();
        let mut db = Db::default();
        db.set_field("CONTEXT", 8, "old_name").unwrap();
        db.set_field("OTHER", 0, "kept").unwrap();
        let before = db.fields.clone();
        let error = db.import_type_library(&library, false).unwrap_err();
        assert!(error.to_string().contains("use --replace"));
        assert_eq!(db.fields, before, "a failed merge changes nothing");

        db.import_type_library(&library, true).unwrap();
        assert_eq!(
            db.fields["CONTEXT"]
                .get(&8)
                .map(|field| field.name.as_str()),
            Some("new_name")
        );
        assert_eq!(
            db.fields["CONTEXT"]
                .get(&0x10)
                .map(|field| field.name.as_str()),
            Some("flags")
        );
        assert_eq!(
            db.fields["OTHER"].get(&0).map(|field| field.name.as_str()),
            Some("kept")
        );
        let _ = std::fs::remove_file(library);
    }

    #[test]
    fn type_library_merge_treats_member_types_as_layout_facts() {
        let library = tmp_path("typelib-type-conflict");
        std::fs::write(
            &library,
            r#"{"schema":1,"types":[{"name":"CONTEXT","fields":[{"offset":"0x8","name":"length","data_type":"uint64_t"}]}]}"#,
        )
        .unwrap();
        let mut db = Db::default();
        db.set_typed_field("CONTEXT", 8, "length", Some("uint32_t"))
            .unwrap();
        let before = db.fields.clone();
        assert!(db
            .import_type_library(&library, false)
            .unwrap_err()
            .to_string()
            .contains("use --replace"));
        assert_eq!(db.fields, before);
        db.import_type_library(&library, true).unwrap();
        assert_eq!(
            db.fields["CONTEXT"][&8].data_type.as_deref(),
            Some("uint64_t")
        );
        let _ = std::fs::remove_file(library);
    }

    #[test]
    fn malformed_or_future_type_libraries_are_rejected_without_mutation() {
        let library = tmp_path("typelib-invalid");
        let mut db = Db::default();
        db.set_field("SAFE", 0, "value").unwrap();
        let before = db.fields.clone();

        std::fs::write(&library, r#"{"schema":2,"types":[]}"#).unwrap();
        assert!(db
            .import_type_library(&library, false)
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
        std::fs::write(
            &library,
            r#"{"schema":1,"types":[{"name":"bad type","fields":[]}]}"#,
        )
        .unwrap();
        assert!(db.import_type_library(&library, false).is_err());
        assert_eq!(db.fields, before);
        let _ = std::fs::remove_file(library);
    }

    #[test]
    fn staged_patches_group_round_trip_apply_and_revert_transactionally() {
        let path = tmp_path("patches");
        let ps = path.to_string_lossy().into_owned();
        let source = [0x10, 0x20, 0x30, 0x40, 0x50];
        let mut db = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        db.stage_patch(&source, 1, &[0xaa, 0xbb]).unwrap();
        db.stage_patch(&source, 3, &[0xcc]).unwrap();
        assert_eq!(db.patch_runs().len(), 1, "adjacent edits coalesce");
        assert_eq!(
            db.apply_patches(source.to_vec()).unwrap(),
            [0x10, 0xaa, 0xbb, 0xcc, 0x50]
        );

        // Updating an overlap retains the true original, and writing that
        // original back removes only that byte from the staged workspace.
        db.stage_patch(&source, 2, &[0x30, 0xdd]).unwrap();
        assert!(!db.patches.contains_key(&2));
        assert_eq!(db.patches[&3].original, 0x40);
        assert_eq!(db.patches[&3].replacement, 0xdd);
        db.save().unwrap();

        let mut back = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        assert_eq!(
            back.apply_patches(source.to_vec()).unwrap(),
            [0x10, 0xaa, 0x30, 0xdd, 0x50]
        );
        let restored = back.clear_patch_run_at(1);
        assert_eq!(restored, [(1, 0x20)]);
        assert_eq!(back.patch_runs()[0].offset, 3);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn staged_patches_reject_bounds_stale_files_and_malformed_hex() {
        let source = [0x10, 0x20, 0x30];
        let mut db = Db::default();
        assert!(db.stage_patch(&source, 3, &[0xff]).is_err());
        assert!(db.stage_patch(&source, 0, &[]).is_err());
        db.stage_patch(&source, 1, &[0xaa]).unwrap();
        let before = db.patches.clone();
        assert!(db.stage_patch(&source, u64::MAX, &[1, 2]).is_err());
        assert_eq!(db.patches, before, "failed staging is atomic");
        assert!(db.apply_patches(vec![0x10, 0x21, 0x30]).is_err());

        assert_eq!(
            parse_patch_bytes("90 0xcc,\\x41").unwrap(),
            [0x90, 0xcc, 0x41]
        );
        assert!(parse_patch_bytes("9").is_err());
        assert!(parse_patch_bytes("zz").is_err());
    }
}
