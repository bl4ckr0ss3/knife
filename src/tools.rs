//! The operation catalog: one source of truth for analysis queries and
//! approved project mutations over a loaded [`Session`].
//!
//! The MCP server (`knife mcp`) exposes this catalog over the same deterministic
//! engine used by CLI/TUI. Each tool takes a `&Session` and returns structured
//! JSON. Full CLI/TUI/MCP query parity remains a separate stabilization task.

use crate::address::{FileOffset, StaticVa};
use crate::analysis::{
    audit, capabilities, driver, engine, entropy, graphs, hardening, hashes, ir, loldrivers,
    signatures, signing, sinks, strings, triage,
};
use crate::api::edits::{apply_analyst_edit, AnalystEdit};
use crate::api::evidence::{
    Confidence, EvidenceKind, EvidenceLocation, EvidenceRecord, EvidenceStatement, OperationResult,
    StatementKind, EVIDENCE_CONTRACT_VERSION,
};
use crate::api::operations::{OperationAvailability, OperationDescriptor, ResultMode};
use crate::api::paging::PageWindow;
use crate::api::persistence::save_analyst_state;
use crate::api::results::ResultStore;
use crate::api::TargetIdentity;
use crate::listing::{self, Annot, Line};
use crate::model::SymKind;
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The most rows any single tool returns, so a consumer never has to cope with
/// an unbounded blob from a pathological binary.
pub const ROW_LIMIT: usize = 400;

fn tool(
    name: &'static str,
    description: &'static str,
    props: Value,
    required: &[&str],
) -> OperationDescriptor {
    OperationDescriptor::read(name, description, props, required)
}

fn mutation(
    name: &'static str,
    description: &'static str,
    props: Value,
    required: &[&str],
) -> OperationDescriptor {
    OperationDescriptor::project_write(name, description, props, required)
}

/// Every read tool, in a stable order. This is the list `tools/list` and the
/// agent's tool schema are both built from.
pub fn read_catalog() -> Vec<OperationDescriptor> {
    let mut operations = vec![
        tool("session_status", "Evidence-aware target identity, analysis coverage, and operation availability for agent workflows.", json!({}), &[]).with_evidence(),
        tool("info", "Format, architecture, entry point, sections, and function/import counts.", json!({}), &[]),
        tool("list_functions", "Recovered functions (address, name, incoming call count), optionally filtered by a name substring.",
             json!({"filter": {"type": "string"}, "limit": {"type": "integer", "minimum": 1}, "cursor": {"type": "string"}, "named_only": {"type": "boolean"}}), &[]).with_result_mode(ResultMode::Paginated),
        tool("inspect_address_context", "Resolve a symbol or static address and report its section, file mapping, containing function, instruction, and cross-reference counts.",
             json!({"selector": {"type": "string"}, "address": {"type": "string", "description": "alias for selector"}}), &[]).with_any_required(&["selector", "address"]).with_evidence(),
        tool("resolve_containing_function", "Resolve the recovered function containing a static address, including the offset from its entry.",
             json!({"address": {"type": "string"}}), &["address"]).with_evidence(),
        tool("address_to_file_offset", "Convert a mapped static virtual address to its file offset and section without conflating address spaces.",
             json!({"address": {"type": "string"}}), &["address"]).with_evidence(),
        tool("read_function_instructions", "Structured, cursor-paginated instructions for a recovered function. An interior address starts the first page at that address.",
             json!({"selector": {"type": "string"}, "address": {"type": "string", "description": "alias for selector"}, "start_address": {"type": "string"}, "limit": {"type": "integer", "minimum": 1}, "cursor": {"type": "string"}}), &[]).with_any_required(&["selector", "address"]).with_result_mode(ResultMode::Paginated).with_evidence(),
        tool("disassemble", "Disassembly of one function. selector is a name or hex address.",
             selector_props(), &[]).with_any_required(&["selector", "address"]),
        tool("decompile", "Decompiled pseudocode for one function.",
             selector_props(), &[]).with_any_required(&["selector", "address"]),
        tool("audit", "Ranked findings: dangerous call sites whose arguments look exploitable, worst first, with reachability.",
             json!({"limit": {"type": "integer"}}), &[]),
        tool("xrefs", "What references (calls/jumps to) an address or function — the callers.",
             selector_props(), &[]).with_any_required(&["selector", "address"]),
        tool("callees", "What one function calls — the outgoing calls, resolved to names.",
             selector_props(), &[]).with_any_required(&["selector", "address"]),
        tool("paths_to", "Call chains that reach a function from the entry point or an export.",
             selector_props(), &[]).with_any_required(&["selector", "address"]),
        tool("trace_taint", "For one function, the exploitable-looking sinks it contains with each dangerous argument's provenance, plus the call chains that reach the function — how caller-controlled input flows to a dangerous call.",
             selector_props(), &[]).with_any_required(&["selector", "address"]),
        tool("strings", "String literals whose text contains a query (empty query lists the first strings), with reference counts.",
             json!({"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1}, "cursor": {"type": "string"}}), &[]).with_result_mode(ResultMode::Paginated),
        tool("iocs", "Indicators of compromise extracted from strings: URLs, hosts, IPs, paths, registry keys.", json!({}), &[]),
        tool("imports", "Imported functions the binary calls out to.", json!({}), &[]),
        tool("exports", "Functions the binary exports.", json!({}), &[]),
        tool(
            "elf_structure",
            "Deterministic ELF header, program-header, or section-header records with on-disk byte ranges.",
            json!({"view": {"type": "string", "enum": ["header", "segments", "section_headers"]}}),
            &["view"],
        ),
        tool("capabilities", "Behavioural capabilities inferred from imports/exports, grouped by category.", json!({}), &[]),
        tool("hardening", "Exploit-mitigation posture: ASLR, DEP/NX, stack canary, CFG, RELRO, and more.", json!({}), &[]),
        tool("triage", "Malware-triage verdict and the signals behind it.", json!({}), &[]),
        tool("signing", "Authenticode / code-signing summary (presence is not validity).", json!({}), &[]),
        tool("hashes", "File hashes (md5/sha1/sha256) and imphash.", json!({}), &[]),
        tool("entropy", "Whole-file Shannon entropy and a bucketed entropy map (spot packed/encrypted regions).", json!({}), &[]),
        tool("driver_report", "Windows-driver / BYOVD surface: devices, IRP dispatch, decoded IOCTLs, and kernel primitives.", json!({}), &[]),
        tool("call_graph", "The call closure rooted at one function (nodes and edges).",
             selector_props(), &[]).with_any_required(&["selector", "address"]),
        tool("sinks", "Dangerous-API call sites (the raw attack surface, by class), before ranking.", json!({}), &[]),
        tool("signatures", "Byte-signature hits: crypto constants, packers, and embedded formats.", json!({}), &[]),
        tool("loldrivers", "Whether this file's sha256 matches a known vulnerable/malicious driver (LOLDrivers).", json!({}), &[]),
        tool("read_bytes", "An exact-length hex+ascii dump at a static virtual address (default 128 bytes, maximum 4096).",
             json!({"address": {"type": "string"}, "length": {"type": "integer", "minimum": 1, "maximum": 4096}}), &["address"]),
    ];
    operations.extend(crate::providers::rizin::catalog());
    operations.extend(crate::providers::yarax::catalog());
    operations
}

/// Analyst-approved project mutations. These alter Knife's saved workspace,
/// never the input binary itself.
pub fn mutation_catalog() -> Vec<OperationDescriptor> {
    let addr = || json!({ "type": "string", "description": "static address (0x...)" });
    vec![
        mutation(
            "set_name",
            "Persist an analyst name for the code at an address.",
            json!({"address": addr(), "name": {"type": "string"}}),
            &["address", "name"],
        ),
        mutation(
            "set_note",
            "Attach an analyst note to an address.",
            json!({"address": addr(), "note": {"type": "string"}}),
            &["address", "note"],
        ),
        mutation(
            "set_prototype",
            "Set a function's return type and ordered parameter types.",
            json!({
                "function": {"type": "string", "description": "function name or static address (0x...)"},
                "returns": {"type": "string"},
                "params": {"type": "array", "items": {"type": "string"}}
            }),
            &["function", "returns"],
        ),
        mutation(
            "stage_patch",
            "Stage replacement bytes at a file offset without modifying the input file.",
            json!({
                "offset": {"type": "string", "description": "file offset (0x...)"},
                "bytes": {"type": "string", "description": "replacement bytes as hex, e.g. 90 90"}
            }),
            &["offset", "bytes"],
        ),
    ]
}

/// Target-free operations over the platform session itself.
pub fn system_catalog() -> Vec<OperationDescriptor> {
    vec![
        OperationDescriptor::system_read(
            "provider_status",
            "Discover optional external analysis providers, versions, safety mode, licenses, limitations, and their operations.",
            json!({}),
            &[],
        ),
        crate::providers::yarax::validation_descriptor(),
        OperationDescriptor::system_read(
            "list_retained_results",
            "List bounded results retained by this Knife process.",
            json!({}),
            &[],
        ),
        OperationDescriptor::system_read(
            "get_retained_result",
            "Retrieve an exact structured result by its result reference.",
            json!({"result_id": {"type": "string"}}),
            &["result_id"],
        ),
    ]
}

/// Every operation available to a front end, in a stable order.
pub fn catalog() -> Vec<OperationDescriptor> {
    let mut operations = system_catalog();
    operations.extend(read_catalog());
    operations.extend(mutation_catalog());
    operations
}

pub fn dispatch_system(store: &ResultStore, name: &str, args: &Value) -> Result<Value> {
    match name {
        "provider_status" => Ok(json!({
            "providers": crate::providers::statuses(),
        })),
        "yarax_validate_rules" => crate::providers::yarax::validate(args),
        "list_retained_results" => Ok(json!({
            "count": store.len(),
            "results": store.summaries(),
        })),
        "get_retained_result" => {
            let id = args
                .get("result_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing `result_id`"))?;
            let retained = store
                .get(id)
                .ok_or_else(|| anyhow!("unknown or expired result reference '{id}'"))?;
            serde_json::to_value(retained).map_err(Into::into)
        }
        other => Err(anyhow!("unknown system operation '{other}'")),
    }
}

/// Run one tool by name against a session, returning structured JSON. Unknown
/// names error. Text-shaped results (disassembly, pseudocode, a hex dump) are
/// returned as a JSON string so a consumer can print them verbatim.
pub fn dispatch(sess: &Session, name: &str, args: &Value) -> Result<Value> {
    match name {
        "session_status" => session_status(sess),
        "info" => Ok(info(sess)),
        "list_functions" => list_functions(sess, args),
        "inspect_address_context" => inspect_address_context(sess, args),
        "resolve_containing_function" => resolve_containing_function(sess, args),
        "address_to_file_offset" => address_to_file_offset(sess, args),
        "read_function_instructions" => read_function_instructions(sess, args),
        "disassemble" => Ok(json!(disassemble(sess, &sel(args)?)?)),
        "decompile" => Ok(json!(decompile(sess, &sel(args)?)?)),
        "audit" => Ok(run_audit(sess, args)),
        "xrefs" => callers(sess, &sel(args)?),
        "callees" => callees(sess, &sel(args)?),
        "paths_to" => paths_to(sess, &sel(args)?),
        "trace_taint" => trace_taint(sess, &sel(args)?),
        "strings" => strings_tool(sess, args),
        "iocs" => Ok(iocs(sess)),
        "imports" => Ok(imports(sess)),
        "exports" => Ok(exports(sess)),
        "elf_structure" => elf_structure(sess, args),
        "capabilities" => Ok(capabilities_tool(sess)),
        "hardening" => serde_json::to_value(hardening::run(&sess.bin)).map_err(Into::into),
        "triage" => Ok(triage_tool(sess)),
        "signing" => {
            serde_json::to_value(signing::summarize(&sess.bin, &sess.bytes)).map_err(Into::into)
        }
        "hashes" => Ok(hashes_tool(sess)),
        "entropy" => Ok(entropy_tool(sess)),
        "driver_report" => driver_report(sess),
        "call_graph" => call_graph(sess, &sel(args)?),
        "sinks" => serde_json::to_value(sinks::find(&sess.an)).map_err(Into::into),
        "signatures" => {
            serde_json::to_value(signatures::scan(&sess.bin, &sess.bytes)).map_err(Into::into)
        }
        "loldrivers" => Ok(loldrivers_tool(sess)),
        "read_bytes" => Ok(json!(read_bytes(sess, args)?)),
        name if crate::providers::rizin::is_operation(name) => rizin_tool(sess, name, args),
        name if crate::providers::yarax::is_operation(name) => yarax_tool(sess, name, args),
        other => Err(anyhow!("unknown tool '{other}'")),
    }
}

/// Run a project mutation through the same typed operation boundary used by
/// every front end. The input binary is never modified.
pub fn dispatch_mut(sess: &mut Session, name: &str, args: &Value) -> Result<Value> {
    match name {
        "set_name" | "set_note" => {
            let address = crate::address::StaticVa(addr_arg(args, "address")?);
            let key = if name == "set_name" { "name" } else { "note" };
            let text = args
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing `{key}`"))?
                .to_string();
            let edit = if name == "set_name" {
                AnalystEdit::SetName {
                    address,
                    name: text.clone(),
                }
            } else {
                AnalystEdit::SetNote {
                    address,
                    note: text.clone(),
                }
            };
            apply_analyst_edit(sess, edit)?;
            save_analyst_state(sess)?;
            Ok(json!({"ok": true, "address": format!("0x{:x}", address.get()), key: text}))
        }
        "set_prototype" => {
            let selector = args
                .get("function")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing `function`"))?;
            let function =
                resolve(&sess.an, selector).ok_or_else(|| anyhow!("no function '{selector}'"))?;
            let address = crate::address::StaticVa(function.addr);
            let function_name = function.name.clone();
            let returns = args
                .get("returns")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing `returns`"))?
                .to_string();
            let params: Vec<String> = args
                .get("params")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            apply_analyst_edit(
                sess,
                AnalystEdit::SetPrototype {
                    function: address,
                    returns: returns.clone(),
                    params: params.clone(),
                },
            )?;
            save_analyst_state(sess)?;
            Ok(json!({
                "ok": true,
                "function": function_name,
                "prototype": format!("{returns} ({})", params.join(", ")),
            }))
        }
        "stage_patch" => {
            let offset = addr_arg(args, "offset")?;
            let encoded = args
                .get("bytes")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing `bytes`"))?;
            let replacement = crate::api::patches::parse_replacement(encoded)?;
            let staged = sess.db.stage_patch(&sess.bytes, offset, &replacement)?;
            save_analyst_state(sess)?;
            Ok(json!({"ok": true, "offset": format!("0x{offset:x}"), "staged": staged}))
        }
        other => Err(anyhow!("unknown project mutation '{other}'")),
    }
}

fn session_status(sess: &Session) -> Result<Value> {
    let identity = TargetIdentity::from_session(sess);
    let mut statements = vec![EvidenceStatement {
        kind: StatementKind::Observation,
        text: format!(
            "Parsed {} {} target and recovered {} functions.",
            identity.architecture, identity.format, identity.functions_recovered
        ),
        confidence: Confidence::Certain,
    }];
    let mut limitations = vec![
        "This session contains static analysis only; it does not establish runtime behavior."
            .to_string(),
        "Unresolved indirect control flow can make call graphs and reachability incomplete."
            .to_string(),
    ];
    if sess.an.truncated {
        statements.push(EvidenceStatement {
            kind: StatementKind::Unknown,
            text: "Function recovery stopped at the configured instruction budget.".into(),
            confidence: Confidence::Certain,
        });
        limitations.push("Analysis is truncated.".into());
    }
    if identity.staged_patch_bytes != 0 {
        statements.push(EvidenceStatement {
            kind: StatementKind::Observation,
            text: format!(
                "The analyzed workspace includes {} staged replacement bytes.",
                identity.staged_patch_bytes
            ),
            confidence: Confidence::Certain,
        });
    }
    let evidence = EvidenceRecord::new(
        &identity.workspace_sha256,
        "session_status",
        EvidenceKind::TargetIdentity,
        "Target identity and current static-analysis coverage",
        vec![],
        statements,
        limitations,
    );
    #[derive(serde::Serialize)]
    struct Status {
        target: TargetIdentity,
        analysis_truncated: bool,
        operations: Vec<OperationAvailability>,
    }

    let status = Status {
        target: identity,
        analysis_truncated: sess.an.truncated,
        operations: catalog()
            .iter()
            .map(|operation| operation_availability(sess, operation))
            .collect(),
    };
    serde_json::to_value(OperationResult::complete(status, vec![evidence])).map_err(Into::into)
}

fn operation_availability(
    sess: &Session,
    operation: &OperationDescriptor,
) -> OperationAvailability {
    let reason = match operation.name {
        "decompile" | "audit" | "trace_taint" | "driver_report" if !sess.bin.arch.is_x86() => {
            Some("the current lifting engine supports x86 and x86-64 only".to_string())
        }
        "elf_structure" if sess.bin.format != crate::model::Format::Elf => {
            Some("the active target is not ELF".to_string())
        }
        name if crate::providers::rizin::is_operation(name) => {
            crate::providers::rizin::unavailable_reason()
        }
        _ => None,
    };
    operation.availability(reason.is_none(), reason)
}

// ── argument + resolution helpers ──────────────────────────────────────────

fn sel(args: &Value) -> Result<String> {
    ["selector", "address", "function"]
        .into_iter()
        .find_map(|key| args.get(key).and_then(Value::as_str))
        .map(str::to_string)
        .ok_or_else(|| anyhow!("missing `selector` (the `address` alias is also accepted)"))
}

fn selector_props() -> Value {
    json!({
        "selector": {"type": "string", "description": "function name or static address (0x...)"},
        "address": {"type": "string", "description": "alias for selector"}
    })
}

/// Resolve a name-or-hex selector to a function.
fn resolve<'a>(an: &'a engine::Analysis, s: &str) -> Option<&'a engine::Function> {
    if let Some(f) = an.find_by_name(s) {
        return Some(f);
    }
    parse_addr(s).and_then(|a| an.find_function(a).or_else(|| an.function_at(a)))
}

fn parse_addr(s: &str) -> Option<u64> {
    let h = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(h, 16).ok()
}

fn addr_arg(args: &Value, key: &str) -> Result<u64> {
    let value = args
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing `{key}`"))?;
    parse_addr(value).ok_or_else(|| anyhow!("bad address '{value}'"))
}

/// Roots for reachability: the entry point plus every export, in the engine's
/// address space.
fn roots(sess: &Session) -> Vec<u64> {
    let base = engine::display_base(&sess.bin);
    let mut r: Vec<u64> = sess
        .bin
        .symbols
        .iter()
        .filter(|y| y.kind == SymKind::Export)
        .map(|y| y.addr + base)
        .collect();
    r.push(sess.bin.entry + base);
    r
}

// ── handlers ────────────────────────────────────────────────────────────────

fn info(sess: &Session) -> Value {
    let an = &sess.an;
    let named = an.functions.iter().filter(|f| f.named).count();
    json!({
        "format": sess.bin.format.label(),
        "arch": sess.bin.arch.label(),
        "bits": sess.bin.bits,
        "entry": format!("0x{:x}", sess.bin.entry),
        "sections": sess.bin.sections.len(),
        "functions": an.functions.len(),
        "named_functions": named,
        "imports": an.imports.len(),
    })
}

fn list_functions(sess: &Session, args: &Value) -> Result<Value> {
    let needle = args
        .get("filter")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let named_only = args
        .get("named_only")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let matched: Vec<_> = sess
        .an
        .functions
        .iter()
        .filter(|f| !named_only || f.named)
        .filter(|f| needle.is_empty() || f.name.to_lowercase().contains(&needle))
        .collect();
    let scope = format!("list_functions:{needle}:{named_only}");
    let page = PageWindow::from_args(args, matched.len(), 200, ROW_LIMIT, &scope)?;
    let rows: Vec<Value> = matched
        .into_iter()
        .skip(page.offset)
        .take(page.limit)
        .map(|f| {
            json!({
                "addr": format!("0x{:x}", f.addr),
                "name": f.name,
                "named": f.named,
                "blocks": f.blocks.len(),
                "incoming": f.incoming,
                "size": f.size,
            })
        })
        .collect();
    Ok(json!({
        "count": sess.an.functions.len(),
        "matched": page.total,
        "returned": rows.len(),
        "next_cursor": page.next_cursor,
        "functions": rows,
    }))
}

fn inspect_address_context(sess: &Session, args: &Value) -> Result<Value> {
    let selector = sel(args)?;
    let address = crate::api::navigation::resolve_address_in(&sess.an, &selector)?.get();
    let base = engine::display_base(&sess.bin);
    let file_offset =
        engine::va_to_off(&sess.bin, base, address).and_then(|offset| u64::try_from(offset).ok());
    let section = section_at(sess, address);
    let function = sess.an.function_at(address);
    let instruction = function.and_then(|function| {
        function
            .blocks
            .iter()
            .flat_map(|block| {
                block
                    .insns
                    .iter()
                    .map(move |instruction| (block, instruction))
            })
            .find(|(_, instruction)| {
                let end = instruction
                    .addr
                    .saturating_add(instruction.bytes().len() as u64);
                address >= instruction.addr && address < end
            })
    });
    let exact_name = sess
        .an
        .names
        .get(&address)
        .or_else(|| sess.an.imports.get(&address));
    let data = json!({
        "input": selector,
        "static_address": format!("0x{address:x}"),
        "file_offset": file_offset.map(|offset| format!("0x{offset:x}")),
        "mapped": section.is_some(),
        "file_backed": file_offset.is_some(),
        "symbol": exact_name,
        "section": section.map(|section| json!({
            "name": section.name,
            "flags": section.flags(),
            "virtual_address": format!("0x{:x}", base.saturating_add(section.vaddr)),
            "virtual_size": section.vsize,
            "file_offset": format!("0x{:x}", section.file_off),
            "file_size": section.file_size,
        })),
        "containing_function": function.map(|function| function_context(function, address)),
        "instruction": instruction.map(|(block, instruction)| instruction_context(sess, block.start, instruction)),
        "references_to": sess.an.xrefs_to.get(&address).map_or(0, Vec::len),
        "references_from": sess.an.xrefs_from.get(&address).map_or(0, Vec::len),
    });

    let mut statements = Vec::new();
    if let Some(offset) = file_offset {
        statements.push(observation(format!(
            "Static address 0x{address:x} maps to file offset 0x{offset:x}."
        )));
    } else {
        statements.push(unknown(format!(
            "Static address 0x{address:x} has no file-backed byte mapping."
        )));
    }
    if let Some(function) = function {
        statements.push(inference(format!(
            "Static recovery places the address inside {} at +0x{:x}.",
            function.name,
            address.saturating_sub(function.addr)
        )));
    } else {
        statements.push(unknown(
            "No recovered function contains this address.".to_string(),
        ));
    }
    evidence_result(
        sess,
        "inspect_address_context",
        format!("Static address context for 0x{address:x}"),
        vec![evidence_location(address, file_offset, exact_name.cloned())],
        statements,
        static_limitations(),
        data,
        false,
        None,
    )
}

fn resolve_containing_function(sess: &Session, args: &Value) -> Result<Value> {
    let address = addr_arg(args, "address")?;
    let function = sess
        .an
        .function_at(address)
        .ok_or_else(|| anyhow!("no recovered function contains 0x{address:x}"))?;
    let file_offset = engine::va_to_off(&sess.bin, engine::display_base(&sess.bin), address)
        .and_then(|offset| u64::try_from(offset).ok());
    let data = function_context(function, address);
    evidence_result(
        sess,
        "resolve_containing_function",
        format!("Containing function for 0x{address:x}"),
        vec![evidence_location(
            address,
            file_offset,
            Some(function.name.clone()),
        )],
        vec![inference(format!(
            "Static control-flow recovery places 0x{address:x} inside {}.",
            function.name
        ))],
        static_limitations(),
        data,
        false,
        None,
    )
}

fn address_to_file_offset(sess: &Session, args: &Value) -> Result<Value> {
    let address = addr_arg(args, "address")?;
    let base = engine::display_base(&sess.bin);
    let offset = engine::va_to_off(&sess.bin, base, address)
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or_else(|| anyhow!("static address 0x{address:x} is not file-backed"))?;
    let section = section_at(sess, address);
    let data = json!({
        "static_address": format!("0x{address:x}"),
        "file_offset": format!("0x{offset:x}"),
        "section": section.map(|section| section.name.clone()),
    });
    evidence_result(
        sess,
        "address_to_file_offset",
        format!("File mapping for static address 0x{address:x}"),
        vec![evidence_location(address, Some(offset), None)],
        vec![observation(format!(
            "Parsed image mappings place static address 0x{address:x} at file offset 0x{offset:x}."
        ))],
        vec!["The mapping describes the on-disk image, not a relocated runtime address.".into()],
        data,
        false,
        None,
    )
}

fn read_function_instructions(sess: &Session, args: &Value) -> Result<Value> {
    let selector = sel(args)?;
    let function = resolve(&sess.an, &selector)
        .ok_or_else(|| anyhow!("no recovered function '{selector}'"))?;
    let start = match args.get("start_address").and_then(Value::as_str) {
        Some(value) => parse_addr(value).ok_or_else(|| anyhow!("bad start address '{value}'"))?,
        None => parse_addr(&selector)
            .filter(|address| {
                sess.an
                    .function_at(*address)
                    .is_some_and(|found| found.addr == function.addr)
            })
            .unwrap_or(function.addr),
    };
    if sess
        .an
        .function_at(start)
        .is_none_or(|found| found.addr != function.addr)
    {
        return Err(anyhow!(
            "start address 0x{start:x} is outside recovered function {}",
            function.name
        ));
    }

    let mut instructions: Vec<_> = function
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .insns
                .iter()
                .map(move |instruction| (block.start, instruction))
        })
        .filter(|(_, instruction)| instruction.addr >= start)
        .collect();
    instructions.sort_by_key(|(_, instruction)| instruction.addr);
    instructions.dedup_by_key(|(_, instruction)| instruction.addr);
    let scope = format!("read_function_instructions:{:x}:{start:x}", function.addr);
    let page = PageWindow::from_args(args, instructions.len(), 100, ROW_LIMIT, &scope)?;
    let rows: Vec<Value> = instructions
        .iter()
        .skip(page.offset)
        .take(page.limit)
        .map(|(block, instruction)| instruction_context(sess, *block, instruction))
        .collect();
    let continuation = page.next_cursor.clone();
    let partial = continuation.is_some();
    let first_address = rows
        .first()
        .and_then(|row| row.get("address"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let data = json!({
        "function": function.name,
        "function_address": format!("0x{:x}", function.addr),
        "start_address": format!("0x{start:x}"),
        "first_address": first_address,
        "matched": page.total,
        "returned": rows.len(),
        "next_cursor": page.next_cursor,
        "instructions": rows,
    });
    let file_offset = engine::va_to_off(&sess.bin, engine::display_base(&sess.bin), start)
        .and_then(|offset| u64::try_from(offset).ok());
    evidence_result(
        sess,
        "read_function_instructions",
        format!(
            "Recovered instructions for {} from 0x{start:x}",
            function.name
        ),
        vec![evidence_location(
            start,
            file_offset,
            Some(function.name.clone()),
        )],
        vec![inference(format!(
            "Static recovery identified {} instruction rows at or after 0x{start:x} in {}.",
            page.total, function.name
        ))],
        static_limitations(),
        data,
        partial,
        continuation,
    )
}

fn section_at(sess: &Session, address: u64) -> Option<&crate::model::Section> {
    let rva = address.checked_sub(engine::display_base(&sess.bin))?;
    sess.bin.sections.iter().find(|section| {
        let span = section.vsize.max(section.file_size);
        rva >= section.vaddr && rva < section.vaddr.saturating_add(span)
    })
}

fn function_context(function: &engine::Function, address: u64) -> Value {
    json!({
        "address": format!("0x{:x}", function.addr),
        "name": function.name,
        "offset": address.saturating_sub(function.addr),
        "size": function.size,
        "basic_blocks": function.blocks.len(),
        "incoming_references": function.incoming,
    })
}

fn instruction_context(
    sess: &Session,
    block_start: u64,
    instruction: &engine::EngineInsn,
) -> Value {
    let text = instruction.text(sess.bin.bits, sess.bin.arch);
    let (mnemonic, operands) = text
        .split_once(char::is_whitespace)
        .map(|(mnemonic, operands)| (mnemonic, operands.trim_start()))
        .unwrap_or((text.as_str(), ""));
    let file_offset =
        engine::va_to_off(&sess.bin, engine::display_base(&sess.bin), instruction.addr)
            .and_then(|offset| u64::try_from(offset).ok());
    json!({
        "address": format!("0x{:x}", instruction.addr),
        "file_offset": file_offset.map(|offset| format!("0x{offset:x}")),
        "block": format!("0x{block_start:x}"),
        "bytes": instruction.bytes().iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" "),
        "mnemonic": mnemonic,
        "operands": operands,
        "text": text,
        "target": instruction.target.map(|target| format!("0x{target:x}")),
        "target_name": instruction.target_name.as_deref(),
        "flow": format!("{:?}", instruction.flow).to_lowercase(),
    })
}

fn evidence_location(
    address: u64,
    file_offset: Option<u64>,
    symbol: Option<String>,
) -> EvidenceLocation {
    EvidenceLocation {
        static_address: Some(StaticVa(address)),
        runtime_address: None,
        file_offset: file_offset.map(FileOffset),
        symbol,
    }
}

fn observation(text: String) -> EvidenceStatement {
    EvidenceStatement {
        kind: StatementKind::Observation,
        text,
        confidence: Confidence::Certain,
    }
}

fn inference(text: String) -> EvidenceStatement {
    EvidenceStatement {
        kind: StatementKind::Inference,
        text,
        confidence: Confidence::High,
    }
}

fn unknown(text: String) -> EvidenceStatement {
    EvidenceStatement {
        kind: StatementKind::Unknown,
        text,
        confidence: Confidence::Unknown,
    }
}

fn static_limitations() -> Vec<String> {
    vec![
        "Function boundaries and instruction reachability are static-analysis inferences.".into(),
        "Unresolved indirect control flow can make function membership and references incomplete."
            .into(),
    ]
}

#[allow(clippy::too_many_arguments)]
fn evidence_result(
    sess: &Session,
    producer: &str,
    summary: String,
    locations: Vec<EvidenceLocation>,
    statements: Vec<EvidenceStatement>,
    limitations: Vec<String>,
    data: Value,
    partial: bool,
    continuation: Option<String>,
) -> Result<Value> {
    let identity = TargetIdentity::from_session(sess);
    let evidence = EvidenceRecord::new(
        identity.workspace_sha256,
        producer,
        EvidenceKind::StaticAnalysis,
        summary,
        locations,
        statements,
        limitations,
    );
    serde_json::to_value(OperationResult {
        contract_version: EVIDENCE_CONTRACT_VERSION,
        data,
        evidence: vec![evidence],
        partial,
        continuation,
    })
    .map_err(Into::into)
}

fn rizin_tool(sess: &Session, name: &str, args: &Value) -> Result<Value> {
    let result = crate::providers::rizin::dispatch(sess, name, args)?;
    let locations = result
        .address
        .map(|address| {
            let file_offset =
                engine::va_to_off(&sess.bin, engine::display_base(&sess.bin), address)
                    .and_then(|offset| u64::try_from(offset).ok());
            vec![evidence_location(address, file_offset, None)]
        })
        .unwrap_or_default();
    let statement = if result.inferred {
        EvidenceStatement {
            kind: StatementKind::Inference,
            text: format!("The external Rizin engine produced static-analysis results for {name}."),
            confidence: Confidence::High,
        }
    } else {
        EvidenceStatement {
            kind: StatementKind::Observation,
            text: format!("The external Rizin parser produced structured results for {name}."),
            confidence: Confidence::Certain,
        }
    };
    evidence_result(
        sess,
        name,
        result.summary,
        locations,
        vec![statement],
        vec![
            "This result came from an optional out-of-process Rizin installation; version and availability are reported by provider_status.".into(),
            "Rizin automatic analysis is static and does not establish runtime behavior.".into(),
            "The provider has a 30-second deadline and an 8 MiB output bound; exceeding either returns an error rather than a partial claim.".into(),
        ],
        result.data,
        result.partial,
        result.continuation,
    )
}

fn yarax_tool(sess: &Session, name: &str, args: &Value) -> Result<Value> {
    let result = crate::providers::yarax::scan(sess, name, args)?;
    let locations = result
        .locations
        .into_iter()
        .map(|(file_offset, static_address)| EvidenceLocation {
            static_address,
            runtime_address: None,
            file_offset,
            symbol: static_address.and_then(|address| {
                sess.an
                    .function_at(address.get())
                    .map(|function| function.name.clone())
            }),
        })
        .collect();
    evidence_result(
        sess,
        name,
        result.summary,
        locations,
        vec![EvidenceStatement {
            kind: StatementKind::Inference,
            text: format!(
                "Native YARA-X evaluated the supplied rules against the Knife workspace for {name}."
            ),
            confidence: Confidence::High,
        }],
        vec![
            "A YARA match establishes that the supplied rule condition matched; the rule author's behavioral interpretation remains an inference.".into(),
            "Scan time and matches per pattern are bounded. A capped match list is not proof that no additional offsets exist.".into(),
            "YARA-X scans static workspace bytes and does not establish runtime behavior.".into(),
        ],
        result.data,
        result.partial,
        result.continuation,
    )
}

fn disassemble(sess: &Session, selector: &str) -> Result<String> {
    let f = resolve(&sess.an, selector).ok_or_else(|| anyhow!("no function '{selector}'"))?;
    let base = engine::display_base(&sess.bin);
    let string_map = listing::string_map(&sess.bin, &sess.bytes, base);
    let hints = if driver::plausibly_a_driver(&sess.bin) {
        driver::listing_hints(&sess.bin, &sess.bytes, &sess.an)
    } else {
        BTreeMap::new()
    };
    Ok(
        listing::function(&sess.an, f, &sess.db, base, &string_map, Some(&hints))
            .iter()
            .take(ROW_LIMIT)
            .map(|l| render_line(l, base))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn decompile(sess: &Session, selector: &str) -> Result<String> {
    let f = resolve(&sess.an, selector).ok_or_else(|| anyhow!("no function '{selector}'"))?;
    let base = engine::display_base(&sess.bin);
    let string_map = listing::string_map(&sess.bin, &sess.bytes, base);
    Ok(ir::decompile(&sess.an, &sess.bin, f, &string_map, &sess.db)
        .into_iter()
        .map(|l| l.text)
        .collect::<Vec<_>>()
        .join("\n"))
}

fn render_line(l: &Line, base: u64) -> String {
    match l {
        Line::Label { text, .. } => format!("{text}:"),
        Line::Data { addr, text } => format!("{:012x}  {text}", addr + base),
        Line::Insn {
            addr,
            mnemonic,
            operands,
            annot,
            ..
        } => {
            let mut s = format!("{:012x}  {mnemonic:<7} {operands}", addr + base);
            if let Some(a) = annot {
                let t = match a {
                    Annot::Note(t) | Annot::Symbol(t) | Annot::Local(t) | Annot::Hint(t) => {
                        t.clone()
                    }
                    Annot::Text(t) => format!("\"{t}\""),
                };
                s.push_str(&format!("  ; {t}"));
            }
            s
        }
    }
}

fn run_audit(sess: &Session, args: &Value) -> Value {
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(ROW_LIMIT)
        .min(ROW_LIMIT);
    let mut findings = audit::run(&sess.an, &sess.bin, &sess.bytes);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.addr.cmp(&b.addr)));
    let rows: Vec<Value> = findings
        .iter()
        .take(limit)
        .map(|f| {
            json!({
                "addr": format!("0x{:x}", f.addr),
                "function": f.func,
                "api": f.api,
                "pattern": f.pattern,
                "severity": f.severity,
                "reachable": f.reachable,
                "detail": f.detail,
            })
        })
        .collect();
    json!({ "count": findings.len(), "findings": rows })
}

fn callers(sess: &Session, selector: &str) -> Result<Value> {
    let an = &sess.an;
    let at = resolve(an, selector)
        .map(|f| f.addr)
        .or_else(|| parse_addr(selector))
        .ok_or_else(|| anyhow!("nothing matches {selector}"))?;
    let rows: Vec<Value> = an
        .xrefs_to
        .get(&at)
        .map(|refs| {
            refs.iter()
                .take(ROW_LIMIT)
                .map(|x| json!({ "from": format!("0x{:x}", x.from), "kind": x.kind.label(), "in": an.function_at(x.from).map(|f| f.name.clone()).unwrap_or_else(|| "-".into()) }))
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({ "to": format!("0x{at:x}"), "count": rows.len(), "callers": rows }))
}

fn callees(sess: &Session, selector: &str) -> Result<Value> {
    let an = &sess.an;
    let f = resolve(an, selector).ok_or_else(|| anyhow!("no function '{selector}'"))?;
    let rows: Vec<Value> = f
        .calls
        .iter()
        .take(ROW_LIMIT)
        .map(|c| json!({ "to": format!("0x{c:x}"), "name": an.label(*c) }))
        .collect();
    Ok(json!({ "from": f.name, "count": rows.len(), "callees": rows }))
}

fn paths_to(sess: &Session, selector: &str) -> Result<Value> {
    let an = &sess.an;
    let target = resolve(an, selector)
        .map(|f| f.addr)
        .or_else(|| parse_addr(selector))
        .ok_or_else(|| anyhow!("nothing matches {selector}"))?;
    let chains = an.paths_to(target, &roots(sess), 8, false);
    let rows: Vec<Value> = chains
        .iter()
        .map(|c| json!(c.iter().map(|a| an.label(*a)).collect::<Vec<_>>()))
        .collect();
    Ok(json!({ "to": format!("0x{target:x}"), "count": rows.len(), "paths": rows }))
}

fn trace_taint(sess: &Session, selector: &str) -> Result<Value> {
    let an = &sess.an;
    let f = resolve(an, selector).ok_or_else(|| anyhow!("no function '{selector}'"))?;
    let fname = f.name.clone();
    let faddr = f.addr;
    // The audit already recovers each sink argument's origin with a bounded
    // backward data-flow walk; this focuses that on one function and pairs it
    // with how the function is reached, so the two together answer "can
    // attacker input get here, and does it drive a dangerous call".
    let findings = audit::run(an, &sess.bin, &sess.bytes);
    let sinks: Vec<Value> = findings
        .iter()
        .filter(|fi| fi.func.as_deref() == Some(fname.as_str()))
        .map(|fi| {
            json!({
                "addr": format!("0x{:x}", fi.addr),
                "api": fi.api,
                "pattern": fi.pattern,
                "severity": fi.severity,
                "reachable": fi.reachable,
                "provenance": fi.detail,
            })
        })
        .collect();
    let chains = an.paths_to(faddr, &roots(sess), 8, false);
    let reached: Vec<Value> = chains
        .iter()
        .map(|c| json!(c.iter().map(|a| an.label(*a)).collect::<Vec<_>>()))
        .collect();
    Ok(json!({
        "function": fname,
        "address": format!("0x{faddr:x}"),
        "reachable_from": reached,
        "sinks": sinks,
        "note": "each sink's provenance says where its dangerous argument came from; an empty sink list means the audit found nothing exploitable-looking here.",
    }))
}

fn strings_tool(sess: &Session, args: &Value) -> Result<Value> {
    let q = args
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let base = engine::display_base(&sess.bin);
    let string_map = listing::string_map(&sess.bin, &sess.bytes, base);
    let matched: Vec<_> = string_map
        .iter()
        .filter(|(_, st)| q.is_empty() || st.text.to_lowercase().contains(&q))
        .collect();
    let page = PageWindow::from_args(args, matched.len(), 80, ROW_LIMIT, &format!("strings:{q}"))?;
    let rows: Vec<Value> = matched
        .into_iter()
        .skip(page.offset)
        .take(page.limit)
        .map(|(addr, st)| json!({ "addr": format!("0x{addr:x}"), "refs": sess.an.xrefs_to.get(addr).map_or(0, Vec::len), "text": st.text }))
        .collect();
    Ok(json!({
        "count": rows.len(),
        "matched": page.total,
        "returned": rows.len(),
        "next_cursor": page.next_cursor,
        "strings": rows,
    }))
}

fn iocs(sess: &Session) -> Value {
    let texts: Vec<String> = strings::extract_located(&sess.bytes, 5)
        .into_iter()
        .map(|l| l.text)
        .collect();
    let iocs = strings::find_iocs(&texts);
    let rows: Vec<Value> = iocs
        .iter()
        .take(ROW_LIMIT)
        .map(|i| json!({ "kind": i.kind, "value": i.value }))
        .collect();
    json!({ "count": rows.len(), "iocs": rows })
}

fn imports(sess: &Session) -> Value {
    let mut names: Vec<&str> = sess.bin.all_imported_functions().collect();
    names.sort_unstable();
    names.dedup();
    let count = names.len();
    json!({ "count": count, "imports": names.iter().take(ROW_LIMIT).collect::<Vec<_>>() })
}

fn exports(sess: &Session) -> Value {
    json!({ "count": sess.bin.exports.len(), "exports": sess.bin.exports.iter().take(ROW_LIMIT).collect::<Vec<_>>() })
}

fn elf_structure(sess: &Session, args: &Value) -> Result<Value> {
    let view = args
        .get("view")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("elf_structure requires view"))?;
    let (report, layout) = crate::api::elf_headers::inspect_with_layout(&sess.bytes)?;
    match view {
        "header" => Ok(json!({
            "header": report.header,
            "fields": layout.header_fields,
        })),
        "segments" => Ok(json!({
            "segments": report.segments,
            "locations": layout.programs,
        })),
        "section_headers" => Ok(json!({
            "sections": report.sections,
            "locations": layout.sections,
        })),
        other => Err(anyhow!(
            "unknown ELF structure view '{other}'; expected header, segments, or section_headers"
        )),
    }
}

fn capabilities_tool(sess: &Session) -> Value {
    let caps = capabilities::matches(
        sess.bin
            .all_imported_functions()
            .chain(sess.bin.exports.iter().map(String::as_str)),
    );
    let mut by_category: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for m in &caps {
        by_category
            .entry(m.category)
            .or_default()
            .push(m.api.clone());
    }
    let mut cats: Vec<Value> = by_category
        .into_iter()
        .map(|(category, mut apis)| {
            apis.sort();
            apis.dedup();
            json!({ "category": category, "apis": apis })
        })
        .collect();
    cats.sort_by(|a, b| {
        b["apis"]
            .as_array()
            .map_or(0, Vec::len)
            .cmp(&a["apis"].as_array().map_or(0, Vec::len))
    });
    json!({ "categories": cats })
}

fn triage_tool(sess: &Session) -> Value {
    let caps = capabilities::matches(
        sess.bin
            .all_imported_functions()
            .chain(sess.bin.exports.iter().map(String::as_str)),
    );
    let verdict = triage::run(&sess.bin, &caps);
    serde_json::to_value(verdict).unwrap_or(Value::Null)
}

fn hashes_tool(sess: &Session) -> Value {
    let h = hashes::file_hashes(&sess.bytes);
    json!({ "md5": h.md5, "sha1": h.sha1, "sha256": h.sha256, "imphash": hashes::imphash(&sess.bin) })
}

fn entropy_tool(sess: &Session) -> Value {
    json!({
        "whole_file": entropy::entropy(&sess.bytes),
        "map": entropy::entropy_map(&sess.bytes, 64),
        "note": "8.0 is maximum; sustained values above ~7.2 suggest compression or encryption.",
    })
}

fn driver_report(sess: &Session) -> Result<Value> {
    if !driver::plausibly_a_driver(&sess.bin) {
        return Ok(json!({ "driver": false, "note": "not a Windows kernel driver" }));
    }
    let base = engine::display_base(&sess.bin);
    let string_map = listing::string_map(&sess.bin, &sess.bytes, base);
    let report = driver::report(&sess.bin, &sess.bytes, &sess.an, &string_map);
    let mut v = serde_json::to_value(report)?;
    if let Value::Object(ref mut m) = v {
        m.insert("driver".into(), json!(true));
    }
    Ok(v)
}

fn call_graph(sess: &Session, selector: &str) -> Result<Value> {
    let f = resolve(&sess.an, selector).ok_or_else(|| anyhow!("no function '{selector}'"))?;
    let mut root = BTreeSet::new();
    root.insert(f.addr);
    let graph = graphs::call_graph(&sess.an.functions, &sess.an.imports, Some(&root));
    serde_json::to_value(graph).map_err(Into::into)
}

fn loldrivers_tool(sess: &Session) -> Value {
    let sha = hashes::file_hashes(&sess.bytes).sha256;
    let hits = loldrivers::lookup(&sha);
    let rows: Vec<Value> = hits
        .iter()
        .map(|e| {
            json!({
                "file": e.file,
                "vendor": e.vendor,
                "product": e.product,
                "category": e.category,
                "signer": e.signer,
            })
        })
        .collect();
    json!({ "sha256": sha, "matched": !rows.is_empty(), "entries": rows })
}

fn read_bytes(sess: &Session, args: &Value) -> Result<String> {
    let a = args
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing `address`"))?;
    let addr = parse_addr(a).ok_or_else(|| anyhow!("bad address '{a}'"))?;
    let length = args
        .get("length")
        .and_then(Value::as_u64)
        .map(|length| usize::try_from(length).unwrap_or(usize::MAX))
        .unwrap_or(128);
    if !(1..=4096).contains(&length) {
        return Err(anyhow!("length must be between 1 and 4096 bytes"));
    }
    let base = engine::display_base(&sess.bin);
    let offset = engine::va_to_off(&sess.bin, base, addr)
        .ok_or_else(|| anyhow!("no file-backed data at {a}"))?;
    let section = section_at(sess, addr).ok_or_else(|| anyhow!("no mapped section at {a}"))?;
    let rva = addr
        .checked_sub(base)
        .ok_or_else(|| anyhow!("address {a} is below the image base"))?;
    let section_delta = rva
        .checked_sub(section.vaddr)
        .ok_or_else(|| anyhow!("address {a} is outside its mapped section"))?;
    let available = section.file_size.saturating_sub(section_delta) as usize;
    if length > available || offset.saturating_add(length) > sess.bytes.len() {
        return Err(anyhow!(
            "requested {length} bytes crosses the file-backed end of section {}; at most {available} bytes are available",
            section.name
        ));
    }
    Ok(sess.bytes[offset..offset + length]
        .chunks(16)
        .enumerate()
        .map(|(row, bytes)| {
            let row_address = addr.saturating_add((row * 16) as u64);
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = bytes
                .iter()
                .map(|byte| {
                    if (0x20..=0x7e).contains(byte) {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{row_address:012x}  {hex:<47}  {ascii}")
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Session;
    use crate::ANALYSIS_BUDGET;

    fn sample() -> Option<Session> {
        // Prefer a real sample if present; skip cleanly otherwise so the test is
        // portable across checkouts that do not ship binaries. `KNIFE_SAMPLE`
        // points the smoke test at any binary locally.
        let env = std::env::var("KNIFE_SAMPLE").ok();
        let fixed = [
            "samples/elgoog.sys",
            "samples/hello.exe",
            "tests/data/hello.exe",
        ];
        for p in env.as_deref().into_iter().chain(fixed) {
            if std::path::Path::new(p).exists() {
                match Session::open(p, None, ANALYSIS_BUDGET, "a test") {
                    Ok(s) => return Some(s),
                    Err(e) => eprintln!("sample {p}: open failed: {e}"),
                }
            }
        }
        None
    }

    #[test]
    fn every_tool_dispatches_to_valid_json() {
        let Some(sess) = sample() else {
            eprintln!(
                "no sample: cwd={:?} env={:?}",
                std::env::current_dir(),
                std::env::var("KNIFE_SAMPLE")
            );
            return;
        };
        // Tools that need a target use the entry function's address.
        let entry = format!("0x{:x}", sess.bin.entry);
        for t in read_catalog() {
            let args = match t.name {
                "disassemble" | "decompile" | "xrefs" | "callees" | "paths_to" | "call_graph"
                | "trace_taint" => {
                    json!({ "selector": entry })
                }
                "read_bytes" => json!({ "address": entry }),
                _ => json!({}),
            };
            // A resolution miss is an acceptable error; a panic or a non-JSON
            // result is not. Dispatch must always return cleanly.
            let _ = dispatch(&sess, t.name, &args);
        }
    }

    #[test]
    fn catalog_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in catalog() {
            assert!(seen.insert(t.name), "duplicate tool name {}", t.name);
        }
    }

    #[test]
    fn catalog_classifies_project_mutations_separately() {
        assert!(
            read_catalog()
                .iter()
                .all(|operation| operation.access
                    == crate::api::operations::OperationAccess::ReadOnly)
        );
        assert!(mutation_catalog().iter().all(|operation| {
            operation.access == crate::api::operations::OperationAccess::ProjectWrite
        }));
        assert_eq!(
            catalog().len(),
            system_catalog().len() + read_catalog().len() + mutation_catalog().len()
        );
    }

    #[test]
    fn elf_structure_tool_uses_the_shared_deterministic_report() {
        let root = std::env::temp_dir().join(format!(
            "knife-elf-tool-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("fixture.elf");
        let database = root.join("fixture.json");
        std::fs::write(&target, crate::formats::fixture::elf_with_plt_call()).unwrap();
        let session = Session::open(
            target.to_str().unwrap(),
            database.to_str(),
            100_000,
            "ELF tool test",
        )
        .unwrap();
        for (view, key) in [
            ("header", "fields"),
            ("segments", "segments"),
            ("section_headers", "sections"),
        ] {
            let value = dispatch(&session, "elf_structure", &json!({"view": view})).unwrap();
            assert!(value.get(key).is_some(), "{view}: {value}");
        }
        assert!(dispatch(&session, "elf_structure", &json!({"view": "invented"})).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
