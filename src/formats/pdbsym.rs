//! Names from a Microsoft PDB.
//!
//! A stripped Windows binary carries almost no symbols of its own: an export
//! table if it is a DLL, and otherwise nothing, so every routine reads as
//! `sub_140001234`. The names are not lost, though — they are in the PDB the
//! compiler wrote, which for Microsoft's own binaries is a public download and
//! for anything built in-house is sitting next to the executable. Reading it is
//! the difference between a listing you have to reconstruct from scratch and
//! one that tells you what each function is called.
//!
//! Only names are taken here. A PDB also describes types, locals and line
//! numbers; those are a larger piece of work and are deliberately not attempted,
//! because a half-applied type is worse than none.
//!
//! The match is checked before anything is used. A PDB from a *different build*
//! of the same program will load perfectly and name every function wrongly —
//! quietly, and in a way that looks like success. The GUID and age in the
//! executable's debug directory exist to prevent exactly that, so a mismatch is
//! refused rather than applied.

use crate::model::{SymKind, Symbol};
use pdb::FallibleIterator;
use std::path::{Path, PathBuf};

/// What happened when names were looked for, so the tool can say which.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Pdb {
    /// The image names no PDB at all.
    NotReferenced,
    /// It names one, but nothing was found to read.
    Missing { wanted: String },
    /// One was found but belongs to another build; nothing was taken from it.
    Mismatch { path: String },
    /// Names were read from this file.
    Loaded { path: String, symbols: usize },
    /// It was found but could not be read.
    Failed { path: String, why: String },
}

impl Pdb {
    /// A short phrase for the info panel.
    pub fn summary(&self) -> String {
        match self {
            Pdb::NotReferenced => "none referenced".into(),
            Pdb::Missing { wanted } => format!("{wanted} not found"),
            Pdb::Mismatch { path } => format!("{path} is from another build, ignored"),
            Pdb::Loaded { path, symbols } => format!("{symbols} names from {path}"),
            Pdb::Failed { path, why } => format!("{path} unreadable: {why}"),
        }
    }
    pub fn is_loaded(&self) -> bool {
        matches!(self, Pdb::Loaded { .. })
    }
}

/// An explicit `--pdb` path, set once before analysis begins.
///
/// A global rather than an argument because `formats::analyze` is reached from a
/// dozen call sites and none of the others have an opinion about symbol files;
/// threading a parameter through all of them to serve one flag would cost more
/// than it explains. Set once at startup, read once per parse.
static OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Point the next parse at a specific PDB.
pub fn set_override(path: Option<String>) {
    *OVERRIDE.lock().unwrap() = path;
}

pub fn override_path() -> Option<String> {
    OVERRIDE.lock().unwrap().clone()
}

/// The build fingerprint an executable records for its PDB.
pub struct Wanted {
    pub name: String,
    pub guid: [u8; 16],
    pub age: u32,
}

/// Where to look, in order: an explicit path, then the recorded name beside the
/// binary. The path baked into the executable is the *build machine's* layout
/// and almost never exists here, so only its file name is used.
fn candidates(binary: &Path, wanted: &Wanted, explicit: Option<&str>) -> Vec<PathBuf> {
    if let Some(p) = explicit {
        return vec![PathBuf::from(p)];
    }
    let mut out = Vec::new();
    let stem = Path::new(&wanted.name)
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&wanted.name));
    if let Some(dir) = binary.parent() {
        out.push(dir.join(&stem));
    }
    out.push(stem);
    out
}

/// Read function names from the PDB belonging to this image.
///
/// `wanted` comes from the executable's own debug directory; when it is absent
/// there is nothing to match against and nothing is read, because a PDB that
/// cannot be checked is a PDB that might belong to something else.
pub fn load(binary: &str, wanted: Option<Wanted>, explicit: Option<&str>) -> (Vec<Symbol>, Pdb) {
    let Some(wanted) = wanted else {
        return (Vec::new(), Pdb::NotReferenced);
    };
    let binary = Path::new(binary);
    for path in candidates(binary, &wanted, explicit) {
        if !path.exists() {
            continue;
        }
        let shown = path.display().to_string();
        return match read(&path, &wanted) {
            Ok(Some(symbols)) => {
                let n = symbols.len();
                (
                    symbols,
                    Pdb::Loaded {
                        path: shown,
                        symbols: n,
                    },
                )
            }
            Ok(None) => (Vec::new(), Pdb::Mismatch { path: shown }),
            Err(why) => (Vec::new(), Pdb::Failed { path: shown, why }),
        };
    }
    (
        Vec::new(),
        Pdb::Missing {
            wanted: wanted.name,
        },
    )
}

/// `Ok(None)` means it was read but describes a different build.
fn read(path: &Path, wanted: &Wanted) -> Result<Option<Vec<Symbol>>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut pdb = pdb::PDB::open(file).map_err(|e| e.to_string())?;

    let info = pdb.pdb_information().map_err(|e| e.to_string())?;
    // Two subtleties, both of which silently reject every PDB if got wrong.
    //
    // The executable stores the GUID with its first three fields little-endian,
    // which is not the order a UUID's bytes come in — compared the obvious way,
    // a PDB that matches perfectly looks like a stranger.
    //
    // And the age in the PDB is not the age in the image: the linker bumps the
    // PDB's every time it writes one, so the rule is that the PDB must be at
    // least as new as the image that references it, not exactly as new. The
    // debug stream carries the age to compare against when it has one.
    let guid_ok = info.guid.to_bytes_le() == wanted.guid;
    let pdb_age = pdb
        .debug_information()
        .ok()
        .and_then(|d| d.age())
        .unwrap_or(info.age);
    if !guid_ok || pdb_age < wanted.age {
        return Ok(None);
    }

    let address_map = pdb.address_map().map_err(|e| e.to_string())?;
    let globals = pdb.global_symbols().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut iter = globals.iter();
    while let Some(sym) = iter.next().map_err(|e| e.to_string())? {
        // Public symbols are the ones with an address; the rest describe types
        // and constants, which this pass does not claim to handle.
        if let Ok(pdb::SymbolData::Public(data)) = sym.parse() {
            if !data.function {
                continue;
            }
            if let Some(rva) = data.offset.to_rva(&address_map) {
                out.push(Symbol {
                    // PE symbol addresses are image-relative; the engine adds
                    // the base itself, exactly as it does for exports.
                    addr: u64::from(rva.0),
                    name: data.name.to_string().into_owned(),
                    kind: SymKind::Func,
                    size: None,
                });
            }
        }
    }
    Ok(Some(out))
}
