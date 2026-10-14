//! Bounded adapter for a user-installed Rizin process.
//!
//! Knife invokes only fixed, JSON-producing static-analysis commands. User
//! input is resolved to a numeric address before it reaches the command string,
//! stdin is closed, output is bounded and drained, and the child is killed at a
//! hard deadline. This is deliberately not an arbitrary Rizin command escape.

use crate::api::operations::{OperationDescriptor, ResultMode};
use crate::api::paging::PageWindow;
use crate::providers::process::{
    executable_identity, find_on_path, run_process, JsonCache, TargetSnapshot,
};
use crate::providers::ProviderStatus;
use crate::workspace::Session;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);
const ROW_LIMIT: usize = 400;
const CACHE_ITEMS: usize = 16;
const CACHE_BYTES: usize = 32 * 1024 * 1024;
static RAW_CACHE: OnceLock<Mutex<JsonCache>> = OnceLock::new();

pub const OPERATION_NAMES: &[&str] = &[
    "rizin_info",
    "rizin_sections",
    "rizin_imports",
    "rizin_exports",
    "rizin_symbols",
    "rizin_strings",
    "rizin_entrypoints",
    "rizin_libraries",
    "rizin_relocations",
    "rizin_classes",
    "rizin_functions",
    "rizin_function_info",
    "rizin_callees",
    "rizin_disassemble",
    "rizin_xrefs_to",
    "rizin_xrefs_from",
    "rizin_cfg",
    "rizin_call_graph",
];

#[derive(Debug)]
pub struct ProviderResult {
    pub data: Value,
    pub summary: String,
    pub address: Option<u64>,
    pub partial: bool,
    pub continuation: Option<String>,
    pub inferred: bool,
}

fn descriptor(
    name: &'static str,
    description: &'static str,
    props: Value,
    required: &[&str],
    paginated: bool,
) -> OperationDescriptor {
    let descriptor = OperationDescriptor::read(name, description, props, required).with_evidence();
    if paginated {
        descriptor.with_result_mode(ResultMode::Paginated)
    } else {
        descriptor
    }
}

fn page_props() -> Value {
    json!({
        "limit": {"type": "integer", "minimum": 1, "maximum": ROW_LIMIT},
        "cursor": {"type": "string"}
    })
}

fn selector_props() -> Value {
    json!({
        "selector": {"type": "string", "description": "Knife symbol or hexadecimal static address"},
        "address": {"type": "string", "description": "alias for selector"},
        "limit": {"type": "integer", "minimum": 1, "maximum": ROW_LIMIT},
        "cursor": {"type": "string"}
    })
}

fn address_props() -> Value {
    json!({
        "selector": {"type": "string", "description": "Knife symbol or hexadecimal static address"},
        "address": {"type": "string", "description": "alias for selector"}
    })
}

pub fn catalog() -> Vec<OperationDescriptor> {
    vec![
        descriptor("rizin_info", "Rizin binary identity, format, architecture, and mitigation metadata from an independent external engine.", json!({}), &[], false),
        descriptor("rizin_sections", "Rizin section and segment mappings with permissions and physical/virtual addresses.", page_props(), &[], true),
        descriptor("rizin_imports", "Imports recovered by Rizin, including ordinals, PLT addresses, and binding metadata.", page_props(), &[], true),
        descriptor("rizin_exports", "Exports recovered by Rizin, including virtual addresses, sizes, and binding metadata.", page_props(), &[], true),
        descriptor("rizin_symbols", "Symbols recovered by Rizin across imports, exports, objects, and functions.", page_props(), &[], true),
        descriptor("rizin_strings", "Strings recovered by Rizin with encodings, sections, and physical/virtual addresses.", page_props(), &[], true),
        descriptor("rizin_entrypoints", "Program, init, and fini entrypoints reported by Rizin.", page_props(), &[], true),
        descriptor("rizin_libraries", "Dynamic libraries reported by Rizin.", page_props(), &[], true),
        descriptor("rizin_relocations", "Relocations reported by Rizin with types and physical/virtual addresses.", page_props(), &[], true),
        descriptor("rizin_classes", "Classes and methods recovered by Rizin from language metadata.", page_props(), &[], true),
        descriptor("rizin_functions", "Functions recovered after Rizin automatic analysis, including signatures, complexity, references, variables, and bounds.", page_props(), &[], true),
        descriptor("rizin_function_info", "Rizin's targeted local recovery of metadata, signature, outgoing references, variables, and bounds for one function.", address_props(), &[], false).with_any_required(&["selector", "address"]),
        descriptor("rizin_callees", "Direct call sites and symbol-resolved targets recovered by Rizin's targeted local analysis of one function.", selector_props(), &[], true).with_any_required(&["selector", "address"]),
        descriptor("rizin_disassemble", "Rizin targeted local function recovery and structured disassembly with opcode bytes, ESIL, flow type, references, and annotations.", selector_props(), &[], true).with_any_required(&["selector", "address"]),
        descriptor("rizin_xrefs_to", "Cross-references Rizin recovered to one static address.", selector_props(), &[], true).with_any_required(&["selector", "address"]),
        descriptor("rizin_xrefs_from", "Cross-references Rizin recovered from one static address after targeted local function recovery.", selector_props(), &[], true).with_any_required(&["selector", "address"]),
        descriptor("rizin_cfg", "Rizin control-flow graph nodes after targeted local recovery of one function.", selector_props(), &[], true).with_any_required(&["selector", "address"]),
        descriptor("rizin_call_graph", "Rizin global call graph after automatic analysis.", page_props(), &[], true),
    ]
}

pub fn is_operation(name: &str) -> bool {
    OPERATION_NAMES.contains(&name)
}

pub fn executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("KNIFE_RIZIN") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    find_on_path("rizin")
}

pub fn unavailable_reason() -> Option<String> {
    executable().is_none().then(|| {
        "Rizin is not installed or not on PATH; install it or set KNIFE_RIZIN to its executable"
            .to_string()
    })
}

pub fn status() -> ProviderStatus {
    let executable = executable();
    let version = executable.as_ref().and_then(|path| version_for(path).ok());
    ProviderStatus {
        id: "rizin",
        name: "Rizin",
        installed: executable.is_some(),
        executable: executable
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        version,
        mode: "out_of_process_static",
        target_execution: false,
        license: "LGPL-3.0-only core; provider invokes a separately installed executable",
        operations: OPERATION_NAMES.to_vec(),
        limitation: unavailable_reason(),
    }
}

pub fn dispatch(session: &Session, name: &str, args: &Value) -> Result<ProviderResult> {
    let executable = executable().ok_or_else(|| {
        anyhow!("Rizin provider is unavailable; install Rizin or set KNIFE_RIZIN to its executable")
    })?;
    let (command, address) = command_for(session, name, args)?;
    let cache_key = cache_key(session, &executable, name, &command);
    if let Some(raw) = raw_cache()
        .lock()
        .map_err(|_| anyhow!("Rizin provider cache is poisoned"))?
        .get(&cache_key)
    {
        return shape_result(session, name, args, address, raw);
    }
    // Analyze the exact immutable workspace bytes Knife identified, not a path
    // that could have changed after the session opened. This also makes staged
    // patch evidence honest without modifying the original target.
    let snapshot = TargetSnapshot::create("rizin", &session.bytes)?;
    let mut raw = run_json(&executable, snapshot.path(), &command)?;
    if name == "rizin_callees" {
        let imports = run_json(&executable, snapshot.path(), "iij")?;
        raw.as_object_mut()
            .ok_or_else(|| anyhow!("Rizin disassembly result is not an object"))?
            .insert("knife_imports".into(), imports);
    }
    raw_cache()
        .lock()
        .map_err(|_| anyhow!("Rizin provider cache is poisoned"))?
        .insert(cache_key, raw.clone());
    shape_result(session, name, args, address, raw)
}

fn raw_cache() -> &'static Mutex<JsonCache> {
    RAW_CACHE.get_or_init(|| Mutex::new(JsonCache::new(CACHE_ITEMS, CACHE_BYTES)))
}

fn cache_key(session: &Session, executable: &Path, operation: &str, command: &str) -> String {
    let workspace_sha256 = crate::analysis::hashes::sha256_hex(&session.bytes);
    let provider_identity = executable_identity(executable);
    format!("{workspace_sha256}:{provider_identity}:{operation}:{command}")
}

fn command_for(session: &Session, name: &str, args: &Value) -> Result<(String, Option<u64>)> {
    let fixed = match name {
        "rizin_info" => Some("ij"),
        "rizin_sections" => Some("iSj"),
        "rizin_imports" => Some("iij"),
        "rizin_exports" => Some("iEj"),
        "rizin_symbols" => Some("isj"),
        "rizin_strings" => Some("izj"),
        "rizin_entrypoints" => Some("iej"),
        "rizin_libraries" => Some("ilj"),
        "rizin_relocations" => Some("irj"),
        "rizin_classes" => Some("icj"),
        "rizin_functions" => Some("aaa;aflj"),
        "rizin_call_graph" => Some("aaa;agC json"),
        _ => None,
    };
    if let Some(command) = fixed {
        return Ok((command.to_string(), None));
    }
    let address = resolve_address(session, args)?;
    let command = match name {
        // Function-scoped operations must remain useful on large firmware ELFs.
        // Defining and analyzing only the selected function avoids making every
        // query pay for whole-program `aaa`; incoming xrefs and global graphs
        // retain whole-program analysis because their contract requires it.
        "rizin_function_info" => format!("af @ 0x{address:x};afij @ 0x{address:x}"),
        "rizin_callees" => format!("af @ 0x{address:x};pdfj @ 0x{address:x}"),
        "rizin_disassemble" => format!("af @ 0x{address:x};pdfj @ 0x{address:x}"),
        "rizin_xrefs_to" => format!("aaa;axtj @ 0x{address:x}"),
        "rizin_xrefs_from" => format!("af @ 0x{address:x};axfj @ 0x{address:x}"),
        "rizin_cfg" => format!("af @ 0x{address:x};agf json @ 0x{address:x}"),
        other => return Err(anyhow!("unknown Rizin operation '{other}'")),
    };
    Ok((command, Some(address)))
}

fn resolve_address(session: &Session, args: &Value) -> Result<u64> {
    let selector = ["selector", "address"]
        .into_iter()
        .find_map(|key| args.get(key).and_then(Value::as_str))
        .ok_or_else(|| anyhow!("missing `selector` (the `address` alias is also accepted)"))?;
    crate::api::navigation::resolve_address_in_session(session, selector)
        .map(|address| address.get())
}

fn shape_result(
    session: &Session,
    name: &str,
    args: &Value,
    address: Option<u64>,
    raw: Value,
) -> Result<ProviderResult> {
    let inferred = matches!(
        name,
        "rizin_functions"
            | "rizin_function_info"
            | "rizin_callees"
            | "rizin_disassemble"
            | "rizin_xrefs_to"
            | "rizin_xrefs_from"
            | "rizin_cfg"
            | "rizin_call_graph"
    );
    let raw_digest = serde_json::to_vec(&raw)
        .map(|encoded| crate::analysis::hashes::sha256_hex(&encoded))
        .unwrap_or_else(|_| "unavailable".to_string());
    let summary = format!("Rizin result for {name} (result sha256 {raw_digest})");
    let (data, partial, continuation) = match name {
        "rizin_info" | "rizin_function_info" => {
            (json!({"provider": "rizin", "result": raw}), false, None)
        }
        "rizin_callees" => page_array(
            args,
            shape_callees(session, &raw)?,
            "rows",
            &scope(name, address),
        )?,
        "rizin_disassemble" => page_object_array(args, raw, "ops", &scope(name, address))?,
        "rizin_cfg" | "rizin_call_graph" => {
            page_object_array(args, raw, "nodes", &scope(name, address))?
        }
        _ => page_array(args, raw, "rows", &scope(name, address))?,
    };
    Ok(ProviderResult {
        data,
        summary,
        address,
        partial,
        continuation,
        inferred,
    })
}

fn shape_callees(session: &Session, raw: &Value) -> Result<Value> {
    let operations = raw
        .get("ops")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Rizin disassembly result has no `ops` array"))?;
    let base = crate::analysis::engine::display_base(&session.bin);
    let imports = raw
        .get("knife_imports")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let rows = operations
        .iter()
        .filter(|operation| operation.get("type").and_then(Value::as_str) == Some("call"))
        .filter_map(|operation| {
            let call_site = operation.get("offset")?.as_u64()?;
            let target = operation.get("jump").and_then(Value::as_u64);
            let target_name = target.and_then(|target| {
                session
                    .an
                    .functions
                    .iter()
                    .find(|function| function.addr == target)
                    .map(|function| function.name.clone())
                    .or_else(|| {
                        session.bin.symbols.iter().find_map(|symbol| {
                            symbol
                                .addr
                                .checked_add(base)
                                .filter(|address| *address == target)
                                .map(|_| symbol.name.clone())
                        })
                    })
                    .or_else(|| {
                        imports.iter().find_map(|import| {
                            if import.get("plt").and_then(Value::as_u64) == Some(target) {
                                import
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .map(str::to_string)
                            } else {
                                None
                            }
                        })
                    })
            });
            Some(json!({
                "call_site": call_site,
                "target": target,
                "target_name": target_name,
                "opcode": operation.get("opcode").cloned().unwrap_or(Value::Null),
                "direct": target.is_some(),
            }))
        })
        .collect::<Vec<_>>();
    Ok(Value::Array(rows))
}

fn scope(name: &str, address: Option<u64>) -> String {
    match address {
        Some(address) => format!("{name}:0x{address:x}"),
        None => name.to_string(),
    }
}

fn page_array(
    args: &Value,
    raw: Value,
    key: &str,
    scope: &str,
) -> Result<(Value, bool, Option<String>)> {
    let rows = raw
        .as_array()
        .ok_or_else(|| anyhow!("Rizin returned an object where an array was expected"))?;
    let page = PageWindow::from_args(args, rows.len(), 100, ROW_LIMIT, scope)?;
    let selected: Vec<_> = rows
        .iter()
        .skip(page.offset)
        .take(page.limit)
        .cloned()
        .collect();
    let continuation = page.next_cursor.clone();
    Ok((
        json!({
            "provider": "rizin",
            "matched": page.total,
            "returned": selected.len(),
            "next_cursor": page.next_cursor,
            key: selected,
        }),
        continuation.is_some(),
        continuation,
    ))
}

fn page_object_array(
    args: &Value,
    raw: Value,
    key: &str,
    scope: &str,
) -> Result<(Value, bool, Option<String>)> {
    let mut object = raw
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("Rizin returned an array where an object was expected"))?;
    let rows = object
        .remove(key)
        .and_then(|rows| rows.as_array().cloned())
        .ok_or_else(|| anyhow!("Rizin result has no `{key}` array"))?;
    let page = PageWindow::from_args(args, rows.len(), 100, ROW_LIMIT, scope)?;
    let selected: Vec<_> = rows
        .into_iter()
        .skip(page.offset)
        .take(page.limit)
        .collect();
    object.insert(key.to_string(), Value::Array(selected.clone()));
    let continuation = page.next_cursor.clone();
    Ok((
        json!({
            "provider": "rizin",
            "matched": page.total,
            "returned": selected.len(),
            "next_cursor": page.next_cursor,
            "result": Value::Object(object),
        }),
        continuation.is_some(),
        continuation,
    ))
}

fn run_json(executable: &Path, target: &Path, command: &str) -> Result<Value> {
    let args = [
        OsString::from("-q"),
        OsString::from("-e"),
        OsString::from("scr.color=false"),
        OsString::from("-e"),
        OsString::from("scr.interactive=false"),
        OsString::from("-c"),
        OsString::from(command),
        target.as_os_str().to_owned(),
    ];
    let output = run_process(executable, args, DEADLINE, OUTPUT_LIMIT)?;
    if output.truncated {
        return Err(anyhow!(
            "Rizin output exceeded the {} MiB provider limit",
            OUTPUT_LIMIT / (1024 * 1024)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Rizin exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    parse_json_output(&stdout).with_context(|| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("Rizin did not return valid JSON; stderr: {}", stderr.trim())
    })
}

fn parse_json_output(output: &str) -> Result<Value> {
    for (index, character) in output.char_indices() {
        if matches!(character, '[' | '{') {
            if let Ok(value) = serde_json::from_str(output[index..].trim()) {
                return Ok(value);
            }
        }
    }
    Err(anyhow!("no complete JSON value in provider output"))
}

fn version_for(executable: &Path) -> Result<String> {
    let output = run_process(
        executable,
        [OsString::from("-v")],
        Duration::from_secs(3),
        OUTPUT_LIMIT,
    )?;
    if !output.status.success() || output.truncated {
        return Err(anyhow!("failed to query Rizin version"));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("Rizin version output was empty"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_prefix_is_removed_before_json_parsing() {
        let parsed = parse_json_output("\u{1b}[2K\r[{\"offset\":4096}]").unwrap();
        assert_eq!(parsed[0]["offset"], 4096);
    }

    #[test]
    fn catalog_is_fixed_unique_and_evidence_aware() {
        let catalog = catalog();
        let mut names = std::collections::BTreeSet::new();
        assert_eq!(catalog.len(), OPERATION_NAMES.len());
        for operation in catalog {
            assert!(names.insert(operation.name));
            assert!(operation.name.starts_with("rizin_"));
            assert!(operation.emits_evidence);
        }
    }

    #[test]
    fn scoped_callees_resolve_rizin_plt_import_targets() {
        let root = std::env::temp_dir().join(format!("knife-rizin-callees-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("fixture.elf");
        let database = root.join("fixture.json");
        std::fs::write(&target, crate::formats::fixture::elf_with_plt_call()).unwrap();
        let session =
            Session::open_data(target.to_str().unwrap(), Some(database.to_str().unwrap())).unwrap();
        let base = crate::analysis::engine::display_base(&session.bin);
        let symbol = session
            .bin
            .symbols
            .iter()
            .find(|symbol| crate::analysis::thunks::bare_name(&symbol.name) == "strcpy")
            .unwrap();
        // Use a provider-reported PLT address distinct from the container
        // symbol so the import join, rather than the first lookup, is tested.
        let target_address = symbol.addr + base + 0x44;
        let raw = json!({
            "knife_imports": [{"name": "strcpy", "plt": target_address}],
            "ops": [
                {"offset": 0x1010, "type": "call", "jump": target_address, "opcode": "call 0x1020"},
                {"offset": 0x1015, "type": "mov", "opcode": "mov eax, eax"}
            ]
        });

        let rows = shape_callees(&session, &raw).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["call_site"], 0x1010);
        assert_eq!(rows[0]["target"], target_address);
        assert_eq!(
            crate::analysis::thunks::bare_name(rows[0]["target_name"].as_str().unwrap()),
            "strcpy"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
