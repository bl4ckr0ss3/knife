//! The operation catalog: one source of truth for analysis queries and
//! approved project mutations over a loaded [`Session`].
//!
//! The MCP server (`knife mcp`) exposes this catalog over the same deterministic
//! engine used by CLI/TUI. Each tool takes a `&Session` and returns structured
//! JSON. Full CLI/TUI/MCP query parity remains a separate stabilization task.

use crate::address::{FileOffset, StaticVa};
use crate::analysis::{
    audit, capabilities, driver, engine, entropy, graphs, hardening, hashes, ir, loldrivers,
    signatures, signing, sinks, strings, triage, wat,
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
        tool("discover_investigation_tools", "Find tools by investigation task (triage, code, strings, validation, memory, external, all), with operation policy and target availability.", json!({"task":{"type":"string","enum":["triage","code","strings","validation","memory","external","all"]}}), &["task"]),
        tool("investigation_status", "Read saved investigation questions, hypotheses, recent conversation, and evidence counts for the active project.", json!({}), &[]),
        tool("investigation_conflicts", "Inspect hypotheses with supporting and contradicting evidence links; this reports recorded conflicts rather than automatically proving contradictions.", json!({}), &[]),
        tool("investigation_get_evidence", "Retrieve one exact persisted evidence record by its ID from the active project investigation.", json!({"evidence_id":{"type":"string"}}), &["evidence_id"]),
        tool("explain_function", "Collect evidence-backed function context, bounded instructions, callers, callees, and pseudocode for an explanation; recovered semantics remain inference.", selector_props(), &[]).with_any_required(&["selector", "address"]).with_evidence(),
        tool("trace_string_usage", "Follow matching string literals to recovered reference instructions and containing functions with bounded coverage and evidence.", json!({"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":20},"cursor":{"type":"string"}}), &["query"]).with_result_mode(ResultMode::Paginated).with_evidence(),
        tool("inspect_input_validation", "Inspect a function's comparison/conditional-branch sites, validation API calls, and dangerous-argument provenance; candidate checks are not proof of a complete validation path.", selector_props(), &[]).with_any_required(&["selector","address"]).with_evidence(),
        tool("compare_engine_findings", "Compare Knife and Rizin function recovery; optionally include Ghidra with explicit include_ghidra. Report disagreements and unknowns with independent evidence.", { let mut props = selector_props(); props["include_ghidra"] = json!({"type":"boolean"}); props["timeout_seconds"] = json!({"type":"integer","minimum":10,"maximum":300}); props }, &[]).with_any_required(&["selector","address"]).with_evidence(),
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
             json!({"query": {"type": "string"}, "pointers": {"type": "boolean", "description": "resolve pointer/length string pairs (bounded to 400 candidates)"}, "limit": {"type": "integer", "minimum": 1}, "cursor": {"type": "string"}}), &[]).with_result_mode(ResultMode::Paginated),
        tool("iocs", "Indicators of compromise extracted from strings: URLs, hosts, IPs, paths, registry keys.", json!({}), &[]),
        tool("imports", "Imported functions the binary calls out to.", json!({}), &[]),
        tool("exports", "Functions the binary exports.", json!({}), &[]),
        tool(
            "elf_structure",
            "Deterministic ELF header, program-header, or section-header records with on-disk byte ranges.",
            json!({"view": {"type": "string", "enum": ["header", "segments", "section_headers"]}}),
            &["view"],
        ),
        tool("wat", "WAT-style listing of one WebAssembly function (selector: name, index, or hex body address), or the function table when omitted.",
             json!({"selector": {"type": "string"}}), &[]),
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
    operations.push(crate::providers::capa::descriptor());
    operations.push(crate::providers::capa::matches_descriptor());
    operations.extend(crate::providers::ghidra::catalog());
    operations.extend(crate::providers::yarax::catalog());
    operations
}

/// Analyst-approved project mutations. These alter Knife's saved workspace,
/// never the input binary itself.
pub fn mutation_catalog() -> Vec<OperationDescriptor> {
    let addr = || json!({ "type": "string", "description": "static address (0x...)" });
    vec![
        mutation("investigation_ask", "Persist an analyst question in the active project's investigation ledger.", json!({"question":{"type":"string","maxLength":32768}}), &["question"]),
        mutation("investigation_add_plan_step", "Add a pending investigation step to the shared project plan.",json!({"text":{"type":"string","maxLength":32768}}), &["text"]),
        mutation("investigation_update_plan_step", "Update a recorded plan step; completion requires saved evidence links.",json!({"step_id":{"type":"integer","minimum":1},"status":{"type":"string","enum":["pending","running","completed","blocked"]},"evidence_ids":{"type":"array","items":{"type":"string"},"maxItems":64}}), &["step_id","status"]),
        mutation("investigation_append_message", "Persist an external agent's conversation or tool-activity entry with optional saved evidence links for the companion TUI.", json!({"role":{"type":"string","enum":["analyst","assistant","tool"]},"text":{"type":"string","maxLength":32768},"evidence_ids":{"type":"array","items":{"type":"string"},"maxItems":64}}), &["role","text"]),
        mutation("investigation_record_evidence", "Persist a content-addressed evidence record for the active target or staged workspace.", json!({"evidence":{"type":"object"}}), &["evidence"]),
        mutation("investigation_link_evidence", "Link saved evidence as supporting or contradicting a hypothesis; opposing links leave it unresolved.", json!({"hypothesis_id":{"type":"integer","minimum":1},"evidence_id":{"type":"string"},"contradicts":{"type":"boolean"}}), &["hypothesis_id","evidence_id","contradicts"]),
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

/// Tools whose answers come from recovered code rather than container facts.
/// The MCP server opens these against a code-analyzed session; everything else
/// also works on architectures without a lifter (wasm, MIPS, …).
pub fn needs_code(name: &str) -> bool {
    matches!(
        name,
        "disassemble"
            | "explain_function"
            | "trace_string_usage"
            | "inspect_input_validation"
            | "compare_engine_findings"
            | "inspect_address_context"
            | "resolve_containing_function"
            | "read_function_instructions"
            | "decompile"
            | "audit"
            | "xrefs"
            | "callees"
            | "paths_to"
            | "trace_taint"
            | "call_graph"
            | "sinks"
    )
}

/// Guard for code tools on a data-only session: refuse with the same shape as
/// `Session::open`'s architecture diagnostic instead of answering from an
/// empty analysis, which would read as "no functions exist".
fn require_code(sess: &Session) -> Result<()> {
    if sess.code_analyzed {
        return Ok(());
    }
    anyhow::bail!(
        "this tool needs x86, x64, or AArch64 disassembly; this is {}",
        sess.bin.arch.label()
    )
}

/// Run one tool by name against a session, returning structured JSON. Unknown
/// names error. Text-shaped results (disassembly, pseudocode, a hex dump) are
/// returned as a JSON string so a consumer can print them verbatim.
pub fn dispatch(sess: &Session, name: &str, args: &Value) -> Result<Value> {
    if needs_code(name) {
        require_code(sess)?;
    }
    match name {
        "session_status" => session_status(sess),
        "ghidra_functions" | "ghidra_decompile" => {
            let data = crate::providers::ghidra::dispatch(sess, name, args)?;
            let partial = data["partial"].as_bool().unwrap_or(true);
            let cursor = data["next_cursor"].as_str().map(str::to_owned);
            evidence_result(sess, name, format!("Ghidra static report {}", data["result_sha256"].as_str().unwrap_or("unknown")), crate::providers::ghidra::evidence_locations(sess, &data), vec![EvidenceStatement { kind: StatementKind::Inference, text: "Ghidra recovered functions or pseudocode from static bytes; this does not demonstrate runtime behavior.".into(), confidence: Confidence::Medium }], vec!["Provider addresses are Ghidra static addresses; only file-backed correlations become Knife navigation locations. No target code was executed.".into(), "Inventory export is capped at 20,000 entries and pseudocode at 65,536 UTF-16 units. Analysis timeouts and decompilation failures are explicit. Cache eviction requires restarting pagination. Engine version is not yet probed.".into()], data, partial, cursor)
        }
        "capa_capabilities" | "capa_rule_matches" => {
            if name == "capa_rule_matches" && args.get("rule").and_then(Value::as_str).is_none() {
                return Err(anyhow!("missing rule"));
            }
            let data = crate::providers::capa::dispatch(sess, args)?;
            let partial = data["partial"].as_bool().unwrap_or(false);
            let cursor = data["next_cursor"].as_str().map(str::to_string);
            evidence_result(sess,name,format!("capa capability matches (result sha256 {})",data["result_sha256"].as_str().unwrap_or("unknown")),crate::providers::capa::evidence_locations(sess,&data),vec![EvidenceStatement{kind:StatementKind::Inference,text:"capa rules matched static features; capability names describe rule interpretations rather than demonstrated execution.".into(),confidence:Confidence::Medium}],vec!["capa match locations retain their declared address kinds. Packed or obfuscated code can make matches incomplete.".into(),"The provider uses a private workspace snapshot, a configurable 1–120-second deadline (30 seconds by default) and an 8 MiB output bound. Each rule reports at most 64 top-level locations. Continuation reuses a bounded cached report; an expired report requires restarting pagination.".into()],data,partial,cursor)
        }
        "discover_investigation_tools" => {
            let task = args
                .get("task")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing task"))?;
            if ![
                "triage",
                "code",
                "strings",
                "validation",
                "memory",
                "external",
                "all",
            ]
            .contains(&task)
            {
                return Err(anyhow!("unknown investigation task"));
            }
            let operations: Vec<_> = read_catalog().into_iter().filter(|operation| match task {
                "triage" => ["session_status","info","triage","hardening","hashes","entropy","signing","capabilities","signatures","imports","exports"].contains(&operation.name),
                "code" => (needs_code(operation.name) && operation.name != "trace_string_usage") || operation.name.starts_with("ghidra_"),
                "strings" => ["strings","trace_string_usage","iocs","read_bytes","inspect_address_context"].contains(&operation.name),
                "validation" => ["inspect_input_validation","explain_function","trace_taint","audit","paths_to","read_function_instructions"].contains(&operation.name),
                "memory" => operation.name.starts_with("investigation_"),
                "external" => operation.name.starts_with("rizin_") || operation.name.starts_with("yarax_") || operation.name.starts_with("capa_") || operation.name.starts_with("ghidra_"),
                _ => true,
            }).map(|operation| json!({"operation":operation,"availability":operation_availability(sess,&operation)})).collect();
            Ok(json!({"task":task,"count":operations.len(),"tools":operations}))
        }
        "investigation_status" => investigation_status(sess),
        "investigation_conflicts" => {
            let ledger = crate::api::investigation::Investigation::load(
                &investigation_path(sess)?,
                &sess.db.sha256,
            )?;
            let conflicts: Vec<_> = ledger
                .hypotheses
                .iter()
                .filter(|hypothesis| {
                    !hypothesis.supports.is_empty() && !hypothesis.contradicts.is_empty()
                })
                .collect();
            let rows: Vec<_> = conflicts.iter().take(100).map(|hypothesis| {
                let linked = |ids: &[crate::api::evidence::EvidenceId]| ids.iter().take(64).filter_map(|id| ledger.evidence.get(&id.0)).map(|record|json!({"id":record.id,"summary":record.summary,"producer":record.producer,"locations":record.locations.iter().take(8).collect::<Vec<_>>()})).collect::<Vec<_>>();
                json!({"hypothesis":hypothesis,"supporting_evidence":linked(&hypothesis.supports),"contradicting_evidence":linked(&hypothesis.contradicts)})
            }).collect();
            Ok(
                json!({"matched":conflicts.len(),"returned":rows.len(),"conflicts":rows,"partial":conflicts.len()>100,"limitation":"These are explicit recorded evidence links. Conflicting interpretations require review; this does not establish that the underlying observations are logically inconsistent."}),
            )
        }
        "investigation_get_evidence" => {
            let id = args
                .get("evidence_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing evidence_id"))?;
            let ledger = crate::api::investigation::Investigation::load(
                &investigation_path(sess)?,
                &sess.db.sha256,
            )?;
            serde_json::to_value(
                ledger
                    .evidence
                    .get(id)
                    .ok_or_else(|| anyhow!("unknown saved evidence"))?,
            )
            .map_err(Into::into)
        }
        "explain_function" => explain_function(sess, args),
        "trace_string_usage" => trace_string_usage(sess, args),
        "inspect_input_validation" => inspect_input_validation(sess, args),
        "compare_engine_findings" => compare_engine_findings(sess, args),
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
        "wat" => Ok(wat_tool(sess, args)),
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
        "investigation_ask"
        | "investigation_add_plan_step"
        | "investigation_update_plan_step"
        | "investigation_append_message"
        | "investigation_record_evidence"
        | "investigation_link_evidence" => investigation_write(sess, name, args),
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
        "ghidra_functions" | "ghidra_decompile"
            if crate::providers::ghidra::executable().is_none() =>
        {
            Some("Ghidra is not configured; set KNIFE_GHIDRA_HEADLESS".into())
        }
        "ghidra_functions" | "ghidra_decompile"
            if std::env::var_os("KNIFE_GHIDRA_WORK_ROOT").is_none() =>
        {
            Some("Ghidra requires KNIFE_GHIDRA_WORK_ROOT".into())
        }
        "ghidra_functions" | "ghidra_decompile"
            if !matches!(
                sess.bin.format,
                crate::model::Format::Pe | crate::model::Format::Elf
            ) =>
        {
            Some("Ghidra initial adapter supports PE and ELF".into())
        }
        "capa_capabilities" | "capa_rule_matches"
            if crate::providers::capa::executable().is_none() =>
        {
            Some("standalone capa is not installed; configure KNIFE_CAPA".into())
        }
        "capa_capabilities" | "capa_rule_matches"
            if !matches!(
                sess.bin.format,
                crate::model::Format::Pe | crate::model::Format::Elf
            ) =>
        {
            Some("capa provider currently supports PE and ELF".into())
        }
        name if needs_code(name) && !sess.code_analyzed => Some(
            "this target has container metadata only; native code analysis is unavailable"
                .to_string(),
        ),
        "wat" if sess.bin.format != crate::model::Format::Wasm => {
            Some("the active target is not WebAssembly".to_string())
        }
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
        "functions": if sess.code_analyzed { Some(an.functions.len()) } else { None },
        "named_functions": if sess.code_analyzed { Some(named) } else { None },
        "code_analyzed": sess.code_analyzed,
        "imports": sess.bin.all_imported_functions().count(),
    })
}

fn investigation_path(sess: &Session) -> Result<std::path::PathBuf> {
    Ok(sess
        .db
        .path()
        .ok_or_else(|| anyhow!("this session has no persistent project"))?
        .with_extension("investigation.json"))
}

fn investigation_status(sess: &Session) -> Result<Value> {
    let ledger = crate::api::investigation::Investigation::load(
        &investigation_path(sess)?,
        &sess.db.sha256,
    )?;
    let hypotheses: Vec<_> = ledger.hypotheses.iter().rev().take(100).collect();
    let messages: Vec<_> = ledger.messages.iter().rev().take(20).collect();
    let plan: Vec<_> = ledger.plan.iter().take(100).collect();
    Ok(
        json!({"target_sha256":ledger.target_sha256,"plan":plan,"plan_count":ledger.plan.len(),"hypotheses":hypotheses,"messages":messages,"evidence_count":ledger.evidence.len(),"hypothesis_count":ledger.hypotheses.len(),"message_count":ledger.messages.len(),"partial":ledger.hypotheses.len()>100 || ledger.messages.len()>20 || ledger.plan.len()>100}),
    )
}

fn investigation_write(sess: &Session, name: &str, args: &Value) -> Result<Value> {
    let path = investigation_path(sess)?;
    let mut ledger = crate::api::investigation::Investigation::load(&path, &sess.db.sha256)?;
    let result = match name {
        "investigation_add_plan_step" => {
            let text = args
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing text"))?
                .to_string();
            json!({"step_id":ledger.add_plan_step(text)?})
        }
        "investigation_update_plan_step" => {
            let id = args
                .get("step_id")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("missing step_id"))?;
            let status: crate::api::investigation::PlanStatus = serde_json::from_value(
                args.get("status")
                    .cloned()
                    .ok_or_else(|| anyhow!("missing status"))?,
            )?;
            let evidence: Vec<crate::api::evidence::EvidenceId> = args
                .get("evidence_ids")
                .map(|value| serde_json::from_value(value.clone()))
                .transpose()?
                .unwrap_or_default();
            if evidence.len() > 64 {
                return Err(anyhow!("at most 64 evidence links are allowed"));
            }
            ledger.update_plan_step(id, status, evidence)?;
            json!({"step_id":id,"status":status})
        }
        "investigation_append_message" => {
            let role: crate::api::investigation::Role = serde_json::from_value(
                args.get("role")
                    .cloned()
                    .ok_or_else(|| anyhow!("missing role"))?,
            )?;
            let text = args
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing text"))?
                .to_string();
            let links: Vec<crate::api::evidence::EvidenceId> = match args.get("evidence_ids") {
                Some(value) => serde_json::from_value(value.clone())?,
                None => Vec::new(),
            };
            if links.len() > 64 {
                return Err(anyhow!("at most 64 evidence links are allowed"));
            }
            ledger.append(role, text, links)?;
            json!({"message_index":ledger.messages.len()-1})
        }
        "investigation_ask" => {
            let question = args
                .get("question")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing question"))?
                .to_string();
            let id = ledger.ask(question.clone())?;
            ledger.append(crate::api::investigation::Role::Analyst, question, vec![])?;
            json!({"hypothesis_id":id})
        }
        "investigation_record_evidence" => {
            let record: EvidenceRecord = serde_json::from_value(
                args.get("evidence")
                    .cloned()
                    .ok_or_else(|| anyhow!("missing evidence"))?,
            )?;
            let rebuilt = EvidenceRecord::new(
                &record.target_sha256,
                &record.producer,
                record.kind,
                &record.summary,
                record.locations.clone(),
                record.statements.clone(),
                record.limitations.clone(),
            );
            if record.id != rebuilt.id {
                return Err(anyhow!("evidence content does not match its ID"));
            }
            if record.target_sha256 != sess.db.sha256
                && record.target_sha256 != hashes::sha256_hex(&sess.bytes)
            {
                return Err(anyhow!("evidence belongs to another target or workspace"));
            }
            let id = record.id.clone();
            ledger.record(record)?;
            json!({"evidence_id":id})
        }
        "investigation_link_evidence" => {
            let hypothesis = args
                .get("hypothesis_id")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("missing hypothesis_id"))?;
            let evidence = args
                .get("evidence_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing evidence_id"))?;
            let contradicts = args
                .get("contradicts")
                .and_then(Value::as_bool)
                .ok_or_else(|| anyhow!("missing contradicts"))?;
            ledger.link(
                hypothesis,
                crate::api::evidence::EvidenceId(evidence.into()),
                contradicts,
            )?;
            json!({"hypothesis_id":hypothesis,"status":ledger.hypotheses.iter().find(|h| h.id==hypothesis).map(|h| h.status)})
        }
        _ => return Err(anyhow!("unknown investigation operation")),
    };
    ledger.save(&path)?;
    Ok(json!({"ok":true,"result":result}))
}

fn explain_function(sess: &Session, args: &Value) -> Result<Value> {
    let selector = sel(args)?;
    let function =
        resolve(&sess.an, &selector).ok_or_else(|| anyhow!("no function '{selector}'"))?;
    let function_selector = format!("0x{:x}", function.addr);
    let instructions =
        read_function_instructions(sess, &json!({"selector":function_selector,"limit":40}))?;
    let pseudocode = match decompile(sess, &function_selector) {
        Ok(value) => {
            json!({"text":value.chars().take(16_000).collect::<String>(),"preview_truncated":value.chars().count() > 16_000})
        }
        Err(error) => json!({"unavailable":error.to_string()}),
    };
    let offset = engine::va_to_off(&sess.bin, engine::display_base(&sess.bin), function.addr)
        .and_then(|value| u64::try_from(value).ok());
    let partial = instructions
        .get("partial")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || pseudocode["preview_truncated"].as_bool().unwrap_or(false);
    let continuation = instructions
        .get("continuation")
        .and_then(Value::as_str)
        .map(str::to_string);
    evidence_result(sess, "explain_function", format!("Explanation inputs for {} at {function_selector}",function.name), vec![evidence_location(function.addr,offset,Some(function.name.clone()))],
        vec![EvidenceStatement { kind:StatementKind::Inference, text:"Function boundaries, references, and pseudocode are recovered static-analysis facts supporting an explanation; they do not establish execution or complete semantics.".into(), confidence:Confidence::Medium }],
        vec!["Instruction coverage is capped at 40 rows; continue with read_function_instructions using its nested continuation cursor.".into(),"Pseudocode is experimental and may leave instructions unmodeled. Callers and callees are bounded by the shared catalog limits.".into()],
        json!({"function":function.name,"address":function_selector,"context":inspect_address_context(sess,&json!({"selector":function_selector}))?,"instructions":instructions,"callers":callers(sess,&function_selector)?,"callees":callees(sess,&function_selector)?,"pseudocode":pseudocode,"explanation_guidance":"Explain the function using cited instructions and references. Label behavior inferred from those observations and explicitly state unresolved indirect flow or incomplete coverage."}), partial, continuation)
}

fn inspect_input_validation(sess: &Session, args: &Value) -> Result<Value> {
    let selector = sel(args)?;
    let function =
        resolve(&sess.an, &selector).ok_or_else(|| anyhow!("no function '{selector}'"))?;
    let mut locations = Vec::new();
    let mut candidates = Vec::new();
    let mut inspected = 0usize;
    let mut partial = false;
    for instruction in function.blocks.iter().flat_map(|block| block.insns.iter()) {
        if inspected == 20_000 {
            partial = true;
            break;
        }
        inspected += 1;
        let text = instruction.text(sess.bin.bits, sess.bin.arch);
        let mnemonic = text.split_whitespace().next().unwrap_or("");
        let target = instruction.target_name.as_deref().unwrap_or("");
        let validation_api = [
            "strcmp", "strncmp", "memcmp", "wcscmp", "wcsncmp", "strtol", "strtoul", "sscanf",
        ]
        .iter()
        .any(|name| target.to_lowercase().contains(name));
        let comparison = matches!(mnemonic, "cmp" | "test" | "cmn" | "tst" | "ccmp");
        let branch = instruction.flow == iced_x86::FlowControl::ConditionalBranch;
        if !(validation_api || comparison || branch) {
            continue;
        }
        if candidates.len() == 64 {
            partial = true;
            continue;
        }
        let offset =
            engine::va_to_off(&sess.bin, engine::display_base(&sess.bin), instruction.addr)
                .and_then(|v| u64::try_from(v).ok());
        locations.push(evidence_location(
            instruction.addr,
            offset,
            Some(function.name.clone()),
        ));
        candidates.push(json!({"address":format!("0x{:x}",instruction.addr),"instruction":text,"comparison":comparison,"conditional_branch":branch,"validation_api_candidate":validation_api,"target_name":instruction.target_name,"target":instruction.target.map(|address|format!("0x{address:x}"))}));
    }
    let provenance = if sess.bin.arch.is_x86() {
        trace_taint(sess, &format!("0x{:x}", function.addr))?
    } else {
        json!({"unavailable":"argument provenance currently supports x86 and x86-64"})
    };
    evidence_result(sess,"inspect_input_validation",format!("Input-validation candidates in {}",function.name),locations,
        vec![EvidenceStatement {kind:StatementKind::Inference,text:"Comparison, branch, and known API sites are candidates for validation. Their relation to caller-controlled input and error/success paths requires further analysis.".into(),confidence:Confidence::Low}],
        vec!["This workflow does not prove that input is accepted, rejected, fully validated, or safe; comparisons may serve unrelated purposes.".into(),"At most 20,000 instructions and 64 candidate sites are inspected/returned. Indirect calls and unrecovered control flow can hide additional checks.".into()],
        json!({"function":function.name,"address":format!("0x{:x}",function.addr),"instructions_inspected":inspected,"candidate_sites":candidates,"argument_provenance":provenance,"callers":callers(sess,&format!("0x{:x}",function.addr))?,"next_steps":["Trace the input-producing calls into each comparison operand","Follow both branch successors to acceptance and rejection paths","Check error handling, truncation and length arithmetic"]}),partial,None)
}

fn compare_engine_findings(sess: &Session, args: &Value) -> Result<Value> {
    let include_ghidra = args
        .get("include_ghidra")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| anyhow!("include_ghidra must be boolean"))
        })
        .transpose()?
        .unwrap_or(false);
    let selector = sel(args)?;
    let address = crate::api::navigation::resolve_address_in(&sess.an, &selector)?.get();
    let native = sess.an.function_at(address);
    let native_data = native
        .map(|function| json!({"address":function.addr,"size":function.size,"name":function.name}));
    let external = if crate::providers::rizin::unavailable_reason().is_none() {
        match rizin_tool(
            sess,
            "rizin_function_info",
            &json!({"address":format!("0x{address:x}")}),
        ) {
            Ok(value) => value,
            Err(error) => json!({"unavailable":error.to_string()}),
        }
    } else {
        json!({"unavailable":crate::providers::rizin::unavailable_reason()})
    };
    let raw = &external["data"]["result"];
    let external_function = raw.as_array().and_then(|rows| rows.first()).unwrap_or(raw);
    let mut comparisons = Vec::new();
    for (field, key) in [("address", "offset"), ("size", "size")] {
        let left = native_data.as_ref().and_then(|value| value[field].as_u64());
        let right = external_function[key].as_u64();
        let status = match (left, right) {
            (Some(a), Some(b)) if a == b => "agreement",
            (Some(_), Some(_)) => "disagreement",
            _ => "unknown",
        };
        comparisons.push(json!({"field":field,"knife":left,"rizin":right,"status":status}));
    }
    let ghidra = if include_ghidra {
        let file_offset = engine::va_to_off(&sess.bin, engine::display_base(&sess.bin), address);
        let report = match file_offset {
            Some(offset) => {
                let mut query = json!({"file_offset":offset,"limit":400});
                if let Some(timeout) = args.get("timeout_seconds") {
                    query["timeout_seconds"] = timeout.clone();
                }
                match dispatch(sess, "ghidra_functions", &query) {
                    Ok(value) => value,
                    Err(error) => json!({"unavailable":error.to_string()}),
                }
            }
            None => {
                json!({"unavailable":"Knife address is not file-backed; Ghidra correlation unknown"})
            }
        };
        let rows = report["data"]["functions"].as_array();
        let candidates = rows
            .into_iter()
            .flatten()
            .filter(|row| crate::providers::ghidra::static_address(sess, row) == Some(address))
            .collect::<Vec<_>>();
        // Multiple aliases/overlays must not silently select an arbitrary row.
        let function = (candidates.len() == 1).then(|| candidates[0]);
        for field in ["address", "size"] {
            let left = native_data.as_ref().and_then(|value| value[field].as_u64());
            let right = function.and_then(|row| {
                if field == "address" {
                    crate::providers::ghidra::static_address(sess, row)
                } else {
                    row["size"].as_u64()
                }
            });
            let status = match (left, right) {
                (Some(a), Some(b)) if a == b => "agreement",
                (Some(_), Some(_)) => "disagreement",
                _ => "unknown",
            };
            comparisons.push(json!({"provider":"ghidra","field":field,"knife":left,"ghidra":right,"status":status}));
        }
        Some(report)
    } else {
        None
    };
    let disagreements = comparisons
        .iter()
        .filter(|row| row["status"] == "disagreement")
        .count();
    let unknowns = comparisons
        .iter()
        .filter(|row| row["status"] == "unknown")
        .count();
    let mut result = evidence_result(sess,"compare_engine_findings",format!("Function recovery comparison at 0x{address:x}: {disagreements} disagreements, {unknowns} unknown fields"),vec![evidence_location(address,engine::va_to_off(&sess.bin,engine::display_base(&sess.bin),address).and_then(|value|u64::try_from(value).ok()),native.map(|function|function.name.clone()))],
        vec![EvidenceStatement{kind:StatementKind::Inference,text:"Different recovered function boundaries are engine disagreements requiring inspection; agreement does not establish correctness or runtime behavior.".into(),confidence:Confidence::Medium}],
        vec!["This compares function entry addresses and reported sizes only. Engines may measure non-contiguous functions differently; a size disagreement is not automatically a bug.".into(),"Unavailable providers or fields remain unknown; neither engine is treated as authoritative.".into(),"When requested, Ghidra is matched by exact entry file offset and checked RAM-space correlation. Missing or ambiguous candidates remain unknown; incomplete inventories cannot establish absence. Address agreement reflects this correlation, not independent proof of semantics.".into()],
        json!({"address":format!("0x{address:x}"),"knife":native_data,"rizin":external,"ghidra":ghidra,"comparisons":comparisons,"disagreements":disagreements,"unknown_fields":unknowns}),unknowns>0,None)?;
    for provider in ["rizin", "ghidra"] {
        if let Some(evidence) = result["data"][provider]["evidence"].as_array().cloned() {
            if let Some(records) = result["evidence"].as_array_mut() {
                records.extend(evidence);
            }
        }
    }
    if result["data"]["ghidra"]["partial"].as_bool() == Some(true) {
        result["partial"] = true.into();
    }
    Ok(result)
}

fn list_functions(sess: &Session, args: &Value) -> Result<Value> {
    if !sess.code_analyzed {
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
            .bin
            .symbols
            .iter()
            .filter(|s| matches!(s.kind, SymKind::Func | SymKind::Export))
            .filter(|s| !named_only || !s.name.is_empty())
            .filter(|s| needle.is_empty() || s.name.to_lowercase().contains(&needle))
            .collect();
        let page = PageWindow::from_args(
            args,
            matched.len(),
            200,
            ROW_LIMIT,
            &format!("list_functions:container:{needle}:{named_only}"),
        )?;
        let rows: Vec<_> = matched.into_iter().skip(page.offset).take(page.limit).map(|s| json!({"addr": format!("0x{:x}", s.addr), "name": s.name, "named": !s.name.is_empty(), "size": s.size, "blocks": null, "incoming": null})).collect();
        return Ok(
            json!({"count": rows.len(), "matched": page.total, "returned": rows.len(), "next_cursor": page.next_cursor, "functions": rows, "note": "Names and sizes come from container metadata; control flow has not been analyzed."}),
        );
    }
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
    if args
        .get("pointers")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let q = args
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        let refs = strings::resolve_pointers(&sess.bin, &sess.bytes, ROW_LIMIT);
        let matched: Vec<_> = refs
            .iter()
            .filter(|r| q.is_empty() || r.text.to_lowercase().contains(&q))
            .collect();
        let page = PageWindow::from_args(
            args,
            matched.len(),
            80,
            ROW_LIMIT,
            &format!("strings:pointers:{q}"),
        )?;
        let rows: Vec<_> = matched.into_iter().skip(page.offset).take(page.limit).map(|r| json!({"addr": format!("0x{:x}", r.addr), "target": format!("0x{:x}", r.target), "len": r.len, "text": r.text})).collect();
        return Ok(
            json!({"count": rows.len(), "matched": page.total, "next_cursor": page.next_cursor, "pointers": rows, "coverage_limit": ROW_LIMIT}),
        );
    }
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

fn trace_string_usage(sess: &Session, args: &Value) -> Result<Value> {
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing query"))?
        .to_lowercase();
    let map = listing::string_map(&sess.bin, &sess.bytes, engine::display_base(&sess.bin));
    let matched: Vec<_> = map
        .iter()
        .filter(|(_, string)| string.text.to_lowercase().contains(&query))
        .collect();
    let page = PageWindow::from_args(
        args,
        matched.len(),
        10,
        20,
        &format!("trace_string_usage:{query}"),
    )?;
    let mut locations = Vec::new();
    let mut reference_truncated = false;
    let rows: Vec<_> = matched.into_iter().skip(page.offset).take(page.limit).map(|(address,string)| {
        let offset = engine::va_to_off(&sess.bin,engine::display_base(&sess.bin),*address).and_then(|v|u64::try_from(v).ok());
        locations.push(evidence_location(*address,offset,None));
        let references = sess.an.xrefs_to.get(address).map(Vec::as_slice).unwrap_or(&[]);
        reference_truncated |= references.len() > 32;
        let sites: Vec<_> = references.iter().take(32).map(|reference| {
            let function = sess.an.function_at(reference.from);
            if locations.len() < 64 {
                let offset = engine::va_to_off(&sess.bin,engine::display_base(&sess.bin),reference.from).and_then(|v|u64::try_from(v).ok());
                locations.push(evidence_location(reference.from,offset,function.map(|f|f.name.clone())));
            }
            json!({"address":format!("0x{:x}",reference.from),"kind":reference.kind.label(),"function":function.map(|f|json!({"address":format!("0x{:x}",f.addr),"name":f.name})),"instruction":function.and_then(|f|f.blocks.iter().flat_map(|block|block.insns.iter()).find(|instruction|instruction.addr==reference.from)).map(|instruction|instruction.text(sess.bin.bits,sess.bin.arch))})
        }).collect();
        json!({"address":format!("0x{address:x}"),"text":string.text,"reference_count":references.len(),"references":sites,"references_truncated":references.len()>32})
    }).collect();
    let continuation = page.next_cursor.clone();
    evidence_result(sess,"trace_string_usage",format!("String usage for query {query:?}"),locations,
        vec![EvidenceStatement { kind:StatementKind::Inference,text:"Recovered static cross-references associate these literals with instructions and functions; they do not establish that a path executes or that all uses were recovered.".into(),confidence:Confidence::Medium }],
        vec!["Indirect references, dynamically constructed strings, and unrecovered code can hide additional uses. Zero references is not proof of non-use.".into(),"Each string returns at most 32 reference sites; string pages contain at most 20 literals.".into()],
        json!({"query":query,"matched":page.total,"returned":rows.len(),"next_cursor":page.next_cursor,"strings":rows}), continuation.is_some()||reference_truncated,continuation)
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

fn wat_tool(sess: &Session, args: &Value) -> Value {
    let selector = args.get("selector").and_then(Value::as_str).unwrap_or("");
    if selector.is_empty() {
        let rows: Vec<Value> = sess
            .bin
            .symbols
            .iter()
            .enumerate()
            .map(|(i, s)| {
                json!({
                    "index": i,
                    "addr": format!("0x{:x}", s.addr),
                    "size": s.size,
                    "name": if s.name.is_empty() { format!("sub_{:x}", s.addr) } else { s.name.clone() },
                })
            })
            .collect();
        return json!({ "count": rows.len(), "functions": rows });
    }
    match wat::render_function(&sess.bin, &sess.bytes, selector) {
        Ok(listing) => json!({ "listing": listing }),
        Err(e) => json!({ "error": e.to_string() }),
    }
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
