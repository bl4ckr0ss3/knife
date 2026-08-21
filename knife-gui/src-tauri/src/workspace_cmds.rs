//! Writing analyst facts: types, fields, prototypes, variables, patches.
//!
//! This is what separates a viewer from a workbench. Everything here goes
//! through `db`, the same store the command line and the terminal interface
//! write, so a type bound in this window is a type `knife pseudo` prints in a
//! terminal a second later.
//!
//! Two paths exist for a reason (see `state.rs`): `annotate` saves and stops,
//! `edit` saves and re-runs recovery. A note changes nothing the engine
//! derived; a name, a type, or a staged patch does.

use crate::commands::parse_addr;
use crate::dto::hex;
use crate::idents::{self, LineActions};
use crate::state::AppState;
use anyhow::{anyhow, Result};
use reknife::analysis::engine;
use reknife::db;
use serde::Serialize;
use tauri::State;

/// Convert a displayed virtual address into the space the database stores.
/// Getting this wrong attaches facts to the wrong instruction on any PE, so it
/// happens in exactly one place.
fn stored(session: &reknife::workspace::Session, va: u64) -> u64 {
    va.wrapping_sub(engine::display_base(&session.bin))
}

// ── names and notes ─────────────────────────────────────────────────────────

#[tauri::command]
pub fn clear_name(state: State<AppState>, addr: String) -> Result<(), String> {
    let at = parse_addr(&addr).map_err(|e| e.to_string())?;
    state
        .edit(|s| {
            s.db.clear_name(stored(s, at));
            Ok(())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_note(state: State<AppState>, addr: String) -> Result<(), String> {
    let at = parse_addr(&addr).map_err(|e| e.to_string())?;
    state
        .annotate(|s| {
            s.db.clear_note(stored(s, at));
            Ok(())
        })
        .map_err(|e| e.to_string())
}

// ── prototypes ──────────────────────────────────────────────────────────────

#[tauri::command]
pub fn set_prototype(
    state: State<AppState>,
    func: String,
    returns: String,
    params: Vec<String>,
) -> Result<(), String> {
    let at = parse_addr(&func).map_err(|e| e.to_string())?;
    let returns = returns.trim().to_string();
    if !db::valid_c_type(&returns) {
        return Err(format!("{returns:?} is not a valid C type"));
    }
    for p in &params {
        if !db::valid_c_type(p.trim()) {
            return Err(format!("{p:?} is not a valid C type"));
        }
    }
    let params: Vec<String> = params.iter().map(|p| p.trim().to_string()).collect();
    state
        .edit(|s| {
            let at = stored(s, at);
            s.db.set_prototype(at, &returns, &params)
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_prototype(state: State<AppState>, func: String) -> Result<(), String> {
    let at = parse_addr(&func).map_err(|e| e.to_string())?;
    state
        .edit(|s| {
            let at = stored(s, at);
            s.db.clear_prototype(at);
            Ok(())
        })
        .map_err(|e| e.to_string())
}

// ── type bindings and structure fields ──────────────────────────────────────

#[tauri::command]
pub fn bind_type(
    state: State<AppState>,
    func: String,
    base: String,
    type_name: String,
) -> Result<(), String> {
    let at = parse_addr(&func).map_err(|e| e.to_string())?;
    let (base, type_name) = (base.trim().to_string(), type_name.trim().to_string());
    if !db::valid_base(&base) {
        return Err(format!("{base:?} is not a pointer base"));
    }
    if !db::valid_identifier(&type_name) {
        return Err(format!("{type_name:?} is not a valid type name"));
    }
    state
        .edit(|s| {
            let at = stored(s, at);
            s.db.bind_type(at, &base, &type_name)
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_binding(state: State<AppState>, func: String, base: String) -> Result<(), String> {
    let at = parse_addr(&func).map_err(|e| e.to_string())?;
    state
        .edit(|s| {
            let at = stored(s, at);
            s.db.clear_binding(at, base.trim());
            Ok(())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_field(
    state: State<AppState>,
    type_name: String,
    offset: i64,
    name: String,
    data_type: Option<String>,
) -> Result<(), String> {
    let (type_name, name) = (type_name.trim().to_string(), name.trim().to_string());
    if !db::valid_identifier(&name) {
        return Err(format!("{name:?} is not a valid field name"));
    }
    let data_type = data_type
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if let Some(t) = &data_type {
        if !db::valid_c_type(t) {
            return Err(format!("{t:?} is not a valid C type"));
        }
    }
    state
        .edit(|s| {
            s.db.set_typed_field(&type_name, offset, &name, data_type.as_deref())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_field(state: State<AppState>, type_name: String, offset: i64) -> Result<(), String> {
    state
        .edit(|s| {
            s.db.clear_field(type_name.trim(), offset);
            Ok(())
        })
        .map_err(|e| e.to_string())
}

// ── pseudocode variable names ───────────────────────────────────────────────

#[tauri::command]
pub fn set_variable(
    state: State<AppState>,
    func: String,
    base: String,
    name: String,
) -> Result<(), String> {
    let at = parse_addr(&func).map_err(|e| e.to_string())?;
    let (base, name) = (base.trim().to_string(), name.trim().to_string());
    if !db::valid_identifier(&name) {
        return Err(format!("{name:?} is not a valid identifier"));
    }
    state
        .edit(|s| {
            let at = stored(s, at);
            s.db.set_variable(at, &base, &name)
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_variable(state: State<AppState>, func: String, base: String) -> Result<(), String> {
    let at = parse_addr(&func).map_err(|e| e.to_string())?;
    state
        .edit(|s| {
            let at = stored(s, at);
            s.db.clear_variable(at, base.trim());
            Ok(())
        })
        .map_err(|e| e.to_string())
}

// ── staged patches ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct PatchRunDto {
    /// File offset of the run.
    pub offset: String,
    /// The virtual address it corresponds to, when it maps to one.
    pub vaddr: Option<String>,
    pub original: String,
    pub bytes: String,
    pub len: usize,
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Stage replacement bytes at a virtual address.
///
/// The original file is never written: patches live in the database with the
/// bytes they expect to replace, and are applied to a copy when the workspace
/// loads. That is what makes an edit reversible and reviewable.
#[tauri::command]
pub fn stage_patch(state: State<AppState>, addr: String, bytes: String) -> Result<usize, String> {
    let va = parse_addr(&addr).map_err(|e| e.to_string())?;
    let replacement = db::parse_patch_bytes(&bytes).map_err(|e| e.to_string())?;
    state
        .edit(|s| {
            let base = engine::display_base(&s.bin);
            let off = engine::va_to_off(&s.bin, base, va)
                .ok_or_else(|| anyhow!("{addr} is not backed by file bytes"))?;
            // `bytes` here is the workspace image, which already has earlier
            // patches applied; `stage_patch` wants the true original, so give it
            // the same view every other staged byte was recorded against.
            let source = s.bytes.clone();
            s.db.stage_patch(&source, off as u64, &replacement)
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_patch(state: State<AppState>, offset: String) -> Result<(), String> {
    let off = parse_addr(&offset).map_err(|e| e.to_string())?;
    state
        .edit(|s| {
            s.db.clear_patch_run_at(off);
            Ok(())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn patch_runs(state: State<AppState>) -> Result<Vec<PatchRunDto>, String> {
    state
        .read(|l| {
            let base = engine::display_base(&l.session.bin);
            Ok(l.session
                .db
                .patch_runs()
                .into_iter()
                .map(|run| PatchRunDto {
                    offset: hex(run.offset),
                    vaddr: engine::off_to_va(&l.session.bin, base, run.offset).map(hex),
                    original: hex_bytes(&run.original),
                    bytes: hex_bytes(&run.bytes),
                    len: run.bytes.len(),
                })
                .collect())
        })
        .map_err(|e| e.to_string())
}

/// Write the patched image out. The target on disk is never touched; this
/// produces a new file, refusing to overwrite the input.
#[tauri::command]
pub fn export_patched(state: State<AppState>, path: String) -> Result<String, String> {
    state
        .read(|l| {
            let out = std::path::Path::new(&path);
            let input = std::fs::canonicalize(&l.session.bin.path).ok();
            if out.exists() && std::fs::canonicalize(out).ok() == input && input.is_some() {
                return Err(anyhow!("refusing to overwrite the input binary"));
            }
            if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            // The workspace bytes already carry every staged patch.
            std::fs::write(out, &l.session.bytes)?;
            Ok(format!("wrote {} bytes to {}", l.session.bytes.len(), path))
        })
        .map_err(|e| e.to_string())
}

// ── the analyst-fact inventory (the Types view) ─────────────────────────────

#[derive(Serialize)]
pub struct FactRow {
    /// "prototype" | "structure" | "binding" | "variable"
    pub kind: &'static str,
    pub name: String,
    pub detail: String,
    /// Where to navigate, for facts that belong to a function.
    pub addr: Option<String>,
}

/// Everything the analyst has told this database, grouped for browsing.
/// Mirrors the terminal interface's type browser.
#[tauri::command]
pub fn analyst_facts(
    state: State<AppState>,
    filter: Option<String>,
) -> Result<Vec<FactRow>, String> {
    let needle = filter.unwrap_or_default().to_lowercase();
    state
        .read(|l| {
            let db = &l.session.db;
            let base = engine::display_base(&l.session.bin);
            let an = &l.session.an;
            let mut rows: Vec<FactRow> = Vec::new();

            for (func, proto) in &db.prototypes {
                let va = func.wrapping_add(base);
                rows.push(FactRow {
                    kind: "prototype",
                    name: an.label(va),
                    detail: format!("{} ({})", proto.returns, proto.params.join(", ")),
                    addr: Some(hex(va)),
                });
            }
            for (type_name, fields) in &db.fields {
                for (offset, field) in fields {
                    let sign = if *offset < 0 { "-" } else { "+" };
                    rows.push(FactRow {
                        kind: "structure",
                        name: type_name.clone(),
                        detail: format!("{sign}0x{:x} {}", offset.unsigned_abs(), field),
                        addr: None,
                    });
                }
            }
            for ((func, base_id), type_name) in &db.bindings {
                let va = func.wrapping_add(base);
                rows.push(FactRow {
                    kind: "binding",
                    name: format!("{}:{}", an.label(va), base_id),
                    detail: format!("{type_name} *"),
                    addr: Some(hex(va)),
                });
            }
            for ((func, base_id), name) in &db.variables {
                let va = func.wrapping_add(base);
                rows.push(FactRow {
                    kind: "variable",
                    name: format!("{}:{}", an.label(va), base_id),
                    detail: name.clone(),
                    addr: Some(hex(va)),
                });
            }

            rows.retain(|r| {
                needle.is_empty()
                    || r.name.to_lowercase().contains(&needle)
                    || r.detail.to_lowercase().contains(&needle)
            });
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn import_typelib(
    state: State<AppState>,
    path: String,
    replace: bool,
) -> Result<String, String> {
    state
        .edit(|s| {
            let summary =
                s.db.import_type_library(std::path::Path::new(&path), replace)?;
            Ok(format!(
                "imported {} type(s), {} field(s)",
                summary.types, summary.fields
            ))
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn export_typelib(state: State<AppState>, path: String) -> Result<String, String> {
    state
        .read(|l| {
            let summary = l
                .session
                .db
                .export_type_library(std::path::Path::new(&path))?;
            Ok(format!(
                "exported {} type(s), {} field(s)",
                summary.types, summary.fields
            ))
        })
        .map_err(|e| e.to_string())
}

/// What each pseudocode line of a function offers: a field reference to retype
/// or name, a variable to rename. Returned alongside the lines so the UI can
/// offer only the actions that actually apply to what was clicked.
#[tauri::command]
pub fn line_actions(state: State<AppState>, func: String) -> Result<Vec<LineActions>, String> {
    let at = parse_addr(&func).map_err(|e| e.to_string())?;
    state
        .read(|l| {
            let an = &l.session.an;
            let f = an
                .find_function(at)
                .or_else(|| an.function_at(at))
                .ok_or_else(|| anyhow!("{func} is not a recovered function"))?;
            let function = stored(&l.session, f.addr);
            let lines =
                reknife::analysis::ir::decompile(an, &l.session.bin, f, &l.strings, &l.session.db);
            Ok(lines
                .iter()
                .map(|line| idents::line_actions(&line.text, function, &l.session.db))
                .collect())
        })
        .map_err(|e| e.to_string())
}
