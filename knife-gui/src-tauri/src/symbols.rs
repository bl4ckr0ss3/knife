//! Imported and exported symbols.
//!
//! The engine already knows every address that reaches an import — stub or slot
//! — and how many instructions point at it. That reference count is the useful
//! part: an import a binary names but never calls tells you far less than the
//! one it calls two hundred times.

use crate::dto::hex;
use crate::state::AppState;
use reknife::analysis::thunks;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct SymbolRow {
    /// Owning module for an import (`KERNEL32`), empty for an export.
    pub module: String,
    pub name: String,
    /// The address to navigate to, when there is one.
    pub addr: Option<String>,
    /// How many instructions reference it.
    pub refs: usize,
}

/// Every import, grouped by module, most-referenced first within each module.
#[tauri::command]
pub fn imports(state: State<AppState>, filter: Option<String>) -> Result<Vec<SymbolRow>, String> {
    let needle = filter.unwrap_or_default().to_lowercase();
    state
        .read(|l| {
            let an = &l.session.an;
            let mut rows: Vec<SymbolRow> = an
                .imports
                .iter()
                .map(|(addr, decorated)| {
                    let module = decorated
                        .rsplit_once('!')
                        .map(|(m, _)| m.to_string())
                        .unwrap_or_default();
                    SymbolRow {
                        module,
                        name: thunks::bare_name(decorated).to_string(),
                        addr: Some(hex(*addr)),
                        refs: an.xrefs_to.get(addr).map_or(0, Vec::len),
                    }
                })
                .filter(|r| {
                    needle.is_empty()
                        || r.name.to_lowercase().contains(&needle)
                        || r.module.to_lowercase().contains(&needle)
                })
                .collect();
            // The same API can arrive through a stub and a slot; keep the entry
            // that is actually referenced rather than showing the pair twice.
            rows.sort_by(|a, b| {
                a.module
                    .cmp(&b.module)
                    .then(a.name.cmp(&b.name))
                    .then(b.refs.cmp(&a.refs))
            });
            rows.dedup_by(|a, b| a.module == b.module && a.name == b.name);
            rows.sort_by(|a, b| a.module.cmp(&b.module).then(b.refs.cmp(&a.refs)));
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

/// Every export, with the address it resolves to when the engine recovered one.
#[tauri::command]
pub fn exports(state: State<AppState>, filter: Option<String>) -> Result<Vec<SymbolRow>, String> {
    let needle = filter.unwrap_or_default().to_lowercase();
    state
        .read(|l| {
            let an = &l.session.an;
            let rows = l
                .session
                .bin
                .exports
                .iter()
                .filter(|name| needle.is_empty() || name.to_lowercase().contains(&needle))
                .map(|name| {
                    let f = an.find_by_name(name);
                    SymbolRow {
                        module: String::new(),
                        name: name.clone(),
                        addr: f.map(|f| hex(f.addr)),
                        refs: f.map_or(0, |f| f.incoming),
                    }
                })
                .collect();
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}
