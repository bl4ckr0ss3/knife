//! Tauri commands: the IPC surface the frontend calls. Each one is a thin
//! mapping onto a `reknife` engine call, exactly like the MCP server's tools —
//! the analysis lives in the library, this file only shapes the request and the
//! reply and turns `anyhow` errors into strings the frontend can show.

use crate::dto::{
    hex, CfgDto, CfgEdge, CfgNode, FindingDto, FnRow, IrLineDto, LineDto, OpenResult, StringRow,
    XrefRow,
};
use crate::state::{AppState, TargetRow};
use anyhow::{anyhow, Result};
use reknife::analysis::engine::{self, Analysis, Function};
use reknife::analysis::{graphs, ir};
use reknife::db;
use reknife::listing;
use reknife::model::SymKind;
use tauri::{Emitter, State};

/// Resolve a selector — a symbol name, or a hex address — to a function.
/// Name first (so a symbol that looks like a number still wins), then the entry
/// address, then the function whose body contains the address. Mirrors
/// `mcp.rs::resolve`.
pub(crate) fn resolve<'a>(an: &'a Analysis, sel: &str) -> Option<&'a Function> {
    if let Some(f) = an.find_by_name(sel) {
        return Some(f);
    }
    let raw = sel.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(raw, 16)
        .ok()
        .and_then(|a| an.find_function(a).or_else(|| an.function_at(a)))
}

/// Parse a `0x…` (or bare hex) address.
pub(crate) fn parse_addr(s: &str) -> Result<u64> {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(raw, 16).map_err(|_| anyhow!("not an address: {s:?}"))
}

/// `func+0x1c` for the site of a cross-reference.
pub(crate) fn site_name(an: &Analysis, addr: u64) -> String {
    match an.function_at(addr) {
        Some(f) => {
            let off = addr.saturating_sub(f.addr);
            if off == 0 {
                f.name.clone()
            } else {
                format!("{}+0x{off:x}", f.name)
            }
        }
        None => "-".to_string(),
    }
}

fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

#[tauri::command]
pub fn open_target(
    app: tauri::AppHandle,
    state: State<AppState>,
    path: String,
) -> Result<OpenResult, String> {
    state
        .open(&path, &|p| {
            let _ = app.emit("knife://phase", p);
        })
        .map_err(|e| e.to_string())?;
    state
        .read(|l| {
            let an = &l.session.an;
            let named = an.functions.iter().filter(|f| f.named).count();
            Ok(OpenResult {
                path: l.session.bin.path.clone(),
                title: basename(&path),
                format: l.session.bin.format.label().to_string(),
                arch: l.session.bin.arch.label().to_string(),
                bits: l.session.bin.bits,
                functions: an.functions.len(),
                named,
                high_risk: l.findings.iter().filter(|f| f.severity >= 3).count(),
                is_driver: l.hints.is_some(),
            })
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_functions(
    state: State<AppState>,
    filter: Option<String>,
    named_only: Option<bool>,
    limit: Option<usize>,
) -> Result<Vec<FnRow>, String> {
    let needle = filter.unwrap_or_default().to_lowercase();
    let named_only = named_only.unwrap_or(false);
    let limit = limit.unwrap_or(usize::MAX);
    state
        .read(|l| {
            let rows = l
                .session
                .an
                .functions
                .iter()
                .filter(|f| !named_only || f.named)
                .filter(|f| needle.is_empty() || f.name.to_lowercase().contains(&needle))
                .take(limit)
                .map(|f| FnRow {
                    addr: hex(f.addr),
                    name: f.name.clone(),
                    named: f.named,
                    size: f.size,
                    blocks: f.blocks.len(),
                    incoming: f.incoming,
                })
                .collect();
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

/// Disassembly for a function, or a hex dump for anything else.
///
/// A string literal and an import slot are both addresses worth navigating to,
/// and neither is inside a recovered function. Falling back to the data view —
/// as the terminal interface does — is what makes every address in the window
/// clickable rather than only the ones that happen to be code.
#[tauri::command]
pub fn disassemble(state: State<AppState>, selector: String) -> Result<Vec<LineDto>, String> {
    state
        .read(|l| {
            if let Some(f) = resolve(&l.session.an, &selector) {
                let lines = listing::function(
                    &l.session.an,
                    f,
                    &l.session.db,
                    l.base,
                    &l.strings,
                    l.hints.as_ref(),
                );
                return Ok(lines.iter().map(LineDto::from).collect());
            }
            let addr =
                parse_addr(&selector).map_err(|_| anyhow!("nothing matches {selector:?}"))?;
            if engine::va_to_off(&l.session.bin, l.base, addr).is_none() {
                return Err(anyhow!("{selector} is not mapped in this image"));
            }
            let lines = listing::data_view(&l.session.bin, l.base, &l.session.bytes, addr);
            Ok(lines.iter().map(LineDto::from).collect())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn decompile(state: State<AppState>, selector: String) -> Result<Vec<IrLineDto>, String> {
    state
        .read(|l| {
            let Some(f) = resolve(&l.session.an, &selector) else {
                // Not a function: there is nothing to decompile, which is a
                // blank tab rather than a failure.
                return Ok(Vec::new());
            };
            let lines = ir::decompile(&l.session.an, &l.session.bin, f, &l.strings, &l.session.db);
            Ok(lines.iter().map(IrLineDto::from).collect())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn xrefs(
    state: State<AppState>,
    addr: String,
    direction: String,
) -> Result<Vec<XrefRow>, String> {
    let target = parse_addr(&addr).map_err(|e| e.to_string())?;
    state
        .read(|l| {
            let an = &l.session.an;
            let rows = if direction == "from" {
                // Callees: the calls the function at `addr` makes.
                let Some(f) = an.find_function(target).or_else(|| an.function_at(target)) else {
                    // A data address makes no calls; the callers direction is
                    // still meaningful and is what the pane shows by default.
                    return Ok(Vec::new());
                };
                f.calls
                    .iter()
                    .map(|&t| XrefRow {
                        addr: hex(t),
                        kind: "call",
                        site: an.label(t),
                    })
                    .collect()
            } else {
                // Callers: who references `addr`.
                an.xrefs_to
                    .get(&target)
                    .map(|refs| {
                        refs.iter()
                            .map(|x| XrefRow {
                                addr: hex(x.from),
                                kind: x.kind.label(),
                                site: site_name(an, x.from),
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn attack_surface(state: State<AppState>) -> Result<Vec<FindingDto>, String> {
    state
        .read(|l| Ok(l.findings.iter().map(FindingDto::from).collect()))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn binary_detail(state: State<AppState>) -> Result<serde_json::Value, String> {
    state
        .read(|l| Ok(l.detail.clone()))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_name(state: State<AppState>, addr: String, name: String) -> Result<(), String> {
    let at = parse_addr(&addr).map_err(|e| e.to_string())?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("a name cannot be empty".to_string());
    }
    if !db::valid_identifier(&name) {
        return Err(format!("{name:?} is not a valid identifier"));
    }
    state
        .edit(|s| {
            let base = engine::display_base(&s.bin);
            s.db.set_name(at.wrapping_sub(base), &name);
            Ok(())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_note(state: State<AppState>, addr: String, note: String) -> Result<(), String> {
    let at = parse_addr(&addr).map_err(|e| e.to_string())?;
    let note = note.trim().to_string();
    if note.is_empty() {
        // Clearing a note without disturbing the name needs a dedicated reknife
        // method that does not exist yet; offer that in a later pass rather than
        // silently dropping the name too (which `Db::clear` would do).
        return Err("an empty note is not supported yet".to_string());
    }
    state
        .annotate(|s| {
            let base = engine::display_base(&s.bin);
            s.db.set_note(at.wrapping_sub(base), &note);
            Ok(())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn cfg(state: State<AppState>, selector: String) -> Result<CfgDto, String> {
    state
        .read(|l| {
            let an = &l.session.an;
            let f =
                resolve(an, &selector).ok_or_else(|| anyhow!("nothing matches {selector:?}"))?;
            // The engine classifies the edges (true / false / flow, and which
            // ones point backwards into a loop); the block bodies come straight
            // off the function so a card can show real instructions.
            let graph = graphs::cfg(f);
            let nodes = f
                .blocks
                .iter()
                .map(|b| CfgNode {
                    id: hex(b.start),
                    addr: hex(b.start),
                    kind: if b.start == f.addr { "entry" } else { "block" },
                    insns: b.insns.iter().map(|i| i.text(an.bits, an.arch)).collect(),
                    count: b.insns.len(),
                    bytes: b.end.saturating_sub(b.start),
                })
                .collect();
            // `graphs` ids blocks its own way; re-key on the address so the
            // frontend has one id space.
            let index: std::collections::BTreeMap<&str, String> = graph
                .nodes
                .iter()
                .map(|n| (n.id.as_str(), hex(n.address)))
                .collect();
            let edges = graph
                .edges
                .iter()
                .filter_map(|e| {
                    Some(CfgEdge {
                        from: index.get(e.from.as_str())?.clone(),
                        to: index.get(e.to.as_str())?.clone(),
                        kind: e.kind,
                        back: e.back,
                    })
                })
                .collect();
            Ok(CfgDto {
                function: f.name.clone(),
                entry: hex(f.addr),
                nodes,
                edges,
            })
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn strings_list(
    state: State<AppState>,
    filter: Option<String>,
    referenced_only: Option<bool>,
    limit: Option<usize>,
) -> Result<Vec<StringRow>, String> {
    let needle = filter.unwrap_or_default().to_lowercase();
    let referenced_only = referenced_only.unwrap_or(false);
    let limit = limit.unwrap_or(5000);
    state
        .read(|l| {
            // `strings` is the literal map the listing already built, keyed by
            // the address code refers to the literal by.
            let rows = l
                .strings
                .iter()
                .filter(|(_, s)| needle.is_empty() || s.text.to_lowercase().contains(&needle))
                .map(|(addr, s)| {
                    let refs = l.session.an.xrefs_to.get(addr).map_or(0, Vec::len);
                    StringRow {
                        addr: hex(*addr),
                        text: s.text.clone(),
                        wide: s.wide,
                        len: s.len,
                        refs,
                    }
                })
                .filter(|r| !referenced_only || r.refs > 0)
                .take(limit)
                .collect();
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

/// The open targets, in tab order.
#[tauri::command]
pub fn list_targets(state: State<AppState>) -> Vec<TargetRow> {
    state.targets()
}

/// Show an already-open target.
#[tauri::command]
pub fn select_target(state: State<AppState>, path: String) -> Result<(), String> {
    state.select(&path).map_err(|e| e.to_string())
}

/// Close a target and free its analysis.
#[tauri::command]
pub fn close_target(state: State<AppState>, path: String) -> Result<(), String> {
    state.close(&path).map_err(|e| e.to_string())
}

/// One call chain that reaches a target.
#[derive(serde::Serialize)]
pub struct PathRow {
    /// Each hop, entry-most first.
    pub hops: Vec<PathHop>,
}

#[derive(serde::Serialize)]
pub struct PathHop {
    pub addr: String,
    pub name: String,
}

/// How control can reach a function from outside.
///
/// The roots are the places control enters the image: the entry point and every
/// export. This is the question a vulnerability is judged by — a dangerous call
/// nothing can reach is a curiosity, and one three hops from an export is a
/// finding — and it is why `reachable` appears on every audit finding.
#[tauri::command]
pub fn paths_to(
    state: State<AppState>,
    selector: String,
    max: Option<usize>,
) -> Result<Vec<PathRow>, String> {
    let max = max.unwrap_or(12).clamp(1, 64);
    state
        .read(|l| {
            let an = &l.session.an;
            let bin = &l.session.bin;
            let target = resolve(an, &selector)
                .map(|f| f.addr)
                .or_else(|| parse_addr(&selector).ok())
                .ok_or_else(|| anyhow!("nothing matches {selector:?}"))?;

            let base = engine::display_base(bin);
            let mut roots: Vec<u64> = bin
                .symbols
                .iter()
                .filter(|s| s.kind == SymKind::Export)
                .map(|s| s.addr + base)
                .collect();
            roots.push(bin.entry + base);

            let mut chains = an.paths_to(target, &roots, max, false);
            chains.sort_by_key(|c| c.len());
            chains.truncate(max);

            Ok(chains
                .into_iter()
                .map(|c| PathRow {
                    hops: c
                        .into_iter()
                        .map(|a| PathHop {
                            addr: hex(a),
                            name: an.label(a),
                        })
                        .collect(),
                })
                .collect())
        })
        .map_err(|e| e.to_string())
}

/// One YARA rule that matched.
#[derive(serde::Serialize)]
pub struct YaraHit {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>,
    /// Pattern identifier and how many times it hit.
    pub patterns: Vec<(String, usize)>,
}

/// Load rules (a file or a directory) and rescan the open target.
///
/// The verdict is recomputed with the matches folded in, which is what
/// `knife info --rules` does; passing no path clears them and puts the score
/// back to the rule-free one.
#[tauri::command]
pub fn set_yara_rules(state: State<AppState>, path: Option<String>) -> Result<usize, String> {
    state
        .set_yara(path.as_deref())
        .map_err(|e| format!("{e:#}"))
}

/// The rules that matched, and what is currently loaded.
#[tauri::command]
pub fn yara_matches(state: State<AppState>) -> Result<(Option<String>, Vec<YaraHit>), String> {
    state
        .read(|l| {
            Ok((
                l.yara_rules.clone(),
                l.yara
                    .iter()
                    .map(|m| YaraHit {
                        rule: m.rule.clone(),
                        namespace: m.namespace.clone(),
                        tags: m.tags.clone(),
                        meta: m.meta.clone(),
                        patterns: m.patterns.clone(),
                    })
                    .collect(),
            ))
        })
        .map_err(|e| e.to_string())
}
