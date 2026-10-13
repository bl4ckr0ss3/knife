//! A Model Context Protocol server (`knife mcp`): a JSON-RPC 2.0 stream over
//! stdio that exposes the analysis as tools, so an agent (ARGUS, or any MCP
//! client) can drive knife directly. It reuses the same engine, listing,
//! decompiler, and audit the command line does; only the wire format is new.
//!
//! The stdio transport is newline-delimited JSON: one message per line, nothing
//! else on stdout (logs go to stderr), so the stream stays clean.
//!
//! A client works on one binary at a time, so the server remembers which one.
//! `knife mcp --file PATH` binds a target up front and the `open` tool binds or
//! replaces it mid-session; after that `file` is optional on every call. Naming
//! an absolute path on each of thirty tool calls is context an agent should be
//! spending on the binary instead, and a path retyped is a path mistyped.

use crate::api::results::{ResultId, ResultStore};
use crate::{tools, workspace::Session, ANALYSIS_BUDGET};
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL: &str = "2024-11-05";

/// What the server tells a client about itself at handshake time. The protocol
/// carries this to the model, and thirty tools with no word on which to reach
/// for first is thirty tools an agent works out the hard way — usually by
/// disassembling everything, when `audit` would have answered the question.
const INSTRUCTIONS: &str = concat!(
    "knife is a static reverse-engineering engine for PE, ELF and Mach-O. It reads\n",
    "the bytes on disk and never executes the target, so it is safe to point at\n",
    "malware.\n",
    "\n",
    "Call `open` with the path first: it binds the target, and every later call may\n",
    "then omit `file`. Call `session_status` next to establish target identity,\n",
    "analysis coverage, limitations, and an evidence record before drawing conclusions.\n",
    "Successful calls include a bounded `knife/resultId`; use `get_retained_result`\n",
    "to retrieve the exact structured payload without rerunning analysis.\n",
    "Call `provider_status` to discover optional external engines. Provider-prefixed\n",
    "tools such as `rizin_functions` are independent static-analysis evidence; use\n",
    "them to corroborate Knife findings, not as proof of runtime behavior.\n",
    "`ghidra_functions` returns provider static addresses and file-backed Knife\n",
    "correlations. `ghidra_decompile` requires `provider_static_address` from that\n",
    "inventory, never a runtime address. Pseudocode is inferred and partial\n",
    "analysis is explicit; use continuation cursors rather than rerunning pages.\n",
    "`yarax_validate_rules`, `yarax_scan`, and `yarax_scan_range` compile bounded\n",
    "inline rules with the native YARA-X engine and report exact match offsets.\n",
    "\n",
    "Where to go next:\n",
    "- `triage`, `hardening`, `signatures`, `entropy` — what the file is, whether it\n",
    "  is packed, and what it is defended by.\n",
    "- `audit` — dangerous call sites ranked by how exploitable their arguments look,\n",
    "  worst first. This is what knife is for; reach for it before reading functions\n",
    "  one at a time. `trace_taint` then says where one argument came from and which\n",
    "  call chains reach it.\n",
    "- `list_functions`, `disassemble`, `decompile` — the code itself. A selector is\n",
    "  a function name or a hex address.\n",
    "- `xrefs`, `callees`, `paths_to`, `call_graph` — how execution reaches a place.\n",
    "- `strings`, `iocs`, `imports`, `exports`, `capabilities` — the behavioural\n",
    "  surface. `driver_report` for Windows kernel drivers.\n",
    "\n",
    "Write down what you work out: `set_name`, `set_note` and `set_prototype` persist\n",
    "beside the binary, so a function named once reads that way in every later\n",
    "listing.\n",
    "\n",
    "Addresses are hex strings such as \"0x1400012a0\". Results are capped at 400 rows.\n",
    "`decompile`, `audit`, `trace_taint` and `driver_report` lift x86/x64 only, and\n",
    "refuse other architectures rather than guess at them.\n",
);

/// The largest single frame we will buffer. MCP frames are one JSON object per
/// line; nothing this server does needs more, so a client that streams a huge
/// line fails closed (the rest of the line is drained and dropped) instead of
/// making us allocate it all.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Read one newline-delimited frame. `Ok(None)` is clean EOF; `Ok(Some(vec))`
/// is a complete line without its newline; a line longer than `MAX_FRAME` is
/// drained to its newline so the stream stays framed, and returned truncated so
/// the caller can tell an oversized frame from a valid one.
fn read_frame(reader: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        if reader.read(&mut byte)? == 0 {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        if byte[0] == b'\n' {
            return Ok(Some(buf));
        }
        if buf.len() < MAX_FRAME {
            buf.push(byte[0]);
        }
    }
}

/// What the server carries between calls.
struct Server {
    /// The binary tool calls act on when they do not name one themselves.
    target: Option<String>,
    /// The last file analysed, cached so repeated tool calls on one target do
    /// not re-run the whole engine each time.
    cache: Option<(String, Session)>,
    /// Bounded structured results addressable by later agent calls.
    results: ResultStore,
}

impl Server {
    fn new(target: Option<String>) -> Self {
        Self {
            target,
            cache: None,
            results: ResultStore::default(),
        }
    }
}

/// Run the server until stdin closes. `target` is the optional `--file` binding.
pub fn run(target: Option<String>) -> Result<()> {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut out = std::io::stdout();
    let mut srv = Server::new(target);

    while let Some(frame) = read_frame(&mut reader)? {
        // A frame we cannot read still gets an answer. Dropping it keeps the
        // stream framed but leaves a client that sent a request waiting for a
        // reply that is never coming, and a hang is a worse failure than an
        // error: there is nothing on the wire to say what went wrong. The id is
        // null because an unparseable frame is exactly the case where we do not
        // know what it was.
        if frame.len() >= MAX_FRAME {
            // The rest of the line was drained, so the stream is still framed.
            parse_error(&mut out, "frame exceeds the maximum size")?;
            continue;
        }
        let line = String::from_utf8_lossy(&frame);
        if line.trim().is_empty() {
            continue; // a blank line is not a message; there is nothing to answer
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            parse_error(&mut out, "frame is not valid JSON")?;
            continue;
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

        // A message with no id is a notification: act on it, never reply.
        let Some(id) = id else {
            continue;
        };

        // The analysis it runs is a black box (dying inputs, adversarial bytes),
        // so contain every request: a panic is reported as an error reply and
        // the poisoned session is dropped so the next call re-analyzes clean.
        let panic_id = id.clone();
        let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match method {
            "initialize" => ok(id.clone(), initialize()),
            "ping" => ok(id.clone(), json!({})),
            "tools/list" => ok(id.clone(), json!({ "tools": tool_list() })),
            "tools/call" => match call_tool(&msg, &mut srv) {
                Ok(result) => ok(id.clone(), tool_success(result)),
                Err(e) => ok(id.clone(), tool_error(&format!("error: {e:#}"))),
            },
            _ => err(id.clone(), -32601, "method not found"),
        }))
        .unwrap_or_else(|_| {
            srv.cache = None; // drop any analysis a panic may have poisoned
            err(panic_id, -32603, "internal error: the analysis panicked")
        });
        writeln!(out, "{}", serde_json::to_string(&reply)?)?;
        out.flush()?;
    }
    Ok(())
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Answer a frame that could not be read at all, per JSON-RPC: a null id,
/// because which request it was is precisely what we could not determine.
fn parse_error(out: &mut impl Write, why: &str) -> Result<()> {
    let reply = err(Value::Null, -32700, why);
    writeln!(out, "{}", serde_json::to_string(&reply)?)?;
    out.flush()?;
    Ok(())
}

fn err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[derive(Debug)]
struct ToolCallOutput {
    text: String,
    structured: Option<Value>,
    result_id: Option<ResultId>,
}

fn tool_success(output: ToolCallOutput) -> Value {
    let mut result = json!({
        "content": [{ "type": "text", "text": output.text }],
        "isError": false,
    });
    if let Some(structured) = output.structured {
        result["structuredContent"] = structured;
    }
    if let Some(result_id) = output.result_id {
        result["_meta"] = json!({ "knife/resultId": result_id });
    }
    result
}

fn tool_error(text: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": true })
}

fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "knife", "version": env!("CARGO_PKG_VERSION") },
        "instructions": INSTRUCTIONS,
    })
}

fn file_arg() -> Value {
    json!({ "type": "string",
            "description": "path to the binary; omit to use the target bound by `open` or by `knife mcp --file`" })
}

fn tool_list() -> Vec<Value> {
    // `open` comes first because it is where a session starts: it is the only
    // tool that must be told a path, and after it none of the others need one.
    let mut all: Vec<Value> = vec![tool(
        "open",
        "Analyse a binary and make it this session's target, so later calls can omit `file`. Returns the same summary as `info`.",
        json!({ "type": "object",
                "properties": { "file": { "type": "string", "description": "path to the binary to analyse" } },
                "required": ["file"] }),
    )];

    // Every operation comes from the shared catalog; MCP adds only its
    // transport-level `file` argument.
    all.extend(tools::catalog().into_iter().map(|t| {
        let mut schema = t.params.clone();
        if t.target == crate::api::operations::TargetRequirement::Active {
            if let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) {
                props.insert("file".into(), file_arg());
            }
        }
        tool_from_operation(&t, schema)
    }));

    all
}

fn tool_from_operation(
    operation: &crate::api::operations::OperationDescriptor,
    schema: Value,
) -> Value {
    let mut tool = tool_with_access(
        operation.name,
        operation.description,
        schema,
        operation.access,
    );
    tool["_meta"]["knife/targetRequirement"] = json!(operation.target);
    tool["_meta"]["knife/resultMode"] = json!(operation.result_mode);
    tool["_meta"]["knife/emitsEvidence"] = json!(operation.emits_evidence);
    tool
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    tool_with_access(
        name,
        description,
        schema,
        crate::api::operations::OperationAccess::ReadOnly,
    )
}

fn tool_with_access(
    name: &str,
    description: &str,
    schema: Value,
    access: crate::api::operations::OperationAccess,
) -> Value {
    use crate::api::operations::OperationAccess;

    let read_only = access == OperationAccess::ReadOnly;
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema,
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": access == OperationAccess::TargetWrite,
            "idempotentHint": read_only,
            "openWorldHint": access == OperationAccess::TargetExecution,
        },
        "_meta": {
            "knife/access": access,
            "knife/evidenceContract": crate::api::evidence::EVIDENCE_CONTRACT_VERSION,
        },
    })
}

fn call_tool(msg: &Value, srv: &mut Server) -> Result<ToolCallOutput> {
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing tool name"))?
        .to_string();
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    // Platform-session operations require no binary and are intentionally not
    // retained themselves: retaining a retrieval would recursively wrap the
    // result ledger.
    if tools::system_catalog().iter().any(|tool| tool.name == name) {
        let value = tools::dispatch_system(&srv.results, &name, &args)?;
        return Ok(output(value, None));
    }

    // A call may name a file, and naming one makes it the target from then on.
    // Otherwise it inherits whatever `--file` or an earlier `open` bound. With
    // nothing bound the error says how to bind something, because "missing
    // `file`" tells an agent what is wrong and not what to do about it.
    let file = match args.get("file").and_then(Value::as_str) {
        Some(f) => {
            srv.target = Some(f.to_string());
            f.to_string()
        }
        None => srv.target.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "no target: pass `file`, call `open`, or start with `knife mcp --file PATH`"
            )
        })?,
    };

    // `open` binds the target and reports what was read, so a client can see
    // the file parsed before it starts asking questions whose answers assume
    // it did. Container facts are enough for that report; the code engine
    // wakes up on the first tool that actually needs it.
    if name == "open" {
        let (value, target_sha256) = {
            let sess = session_data(&mut srv.cache, &file)?;
            let info = tools::dispatch(sess, "info", &json!({}))?;
            (
                json!({ "ok": true, "target": file, "info": info }),
                crate::analysis::hashes::sha256_hex(&sess.bytes),
            )
        };
        return Ok(retain_output(srv, &name, Some(&target_sha256), value));
    }

    // Read tools dispatch through the shared catalog. A string result (a
    // disassembly, pseudocode, a hex dump) is returned verbatim; anything else
    // is JSON.
    if tools::read_catalog().iter().any(|t| t.name == name) {
        let (value, target_sha256) = {
            let native = matches!(
                session_data(&mut srv.cache, &file)?.bin.arch,
                crate::model::Arch::X86 | crate::model::Arch::X86_64 | crate::model::Arch::Aarch64
            );
            let sess = if tools::needs_code(&name) || native {
                session(&mut srv.cache, &file)?
            } else {
                session_data(&mut srv.cache, &file)?
            };
            (
                tools::dispatch(sess, &name, &args)?,
                crate::analysis::hashes::sha256_hex(&sess.bytes),
            )
        };
        return Ok(retain_output(srv, &name, Some(&target_sha256), value));
    }

    if tools::mutation_catalog().iter().any(|t| t.name == name) {
        let (result, target_sha256) = {
            let sess = session_mut(&mut srv.cache, &file)?;
            (
                tools::dispatch_mut(sess, &name, &args)?,
                crate::analysis::hashes::sha256_hex(&sess.bytes),
            )
        };
        // Reopen on the next read so names feed function recovery and staged
        // bytes feed parsing/analysis instead of leaving the bound session
        // stale after a successful project mutation.
        srv.cache = None;
        return Ok(retain_output(srv, &name, Some(&target_sha256), result));
    }

    anyhow::bail!("unknown tool '{name}'")
}

fn output(value: Value, result_id: Option<ResultId>) -> ToolCallOutput {
    match value {
        Value::String(text) => ToolCallOutput {
            text,
            structured: None,
            result_id,
        },
        structured => ToolCallOutput {
            text: structured.to_string(),
            structured: Some(structured),
            result_id,
        },
    }
}

fn retain_output(
    srv: &mut Server,
    operation: &str,
    target_sha256: Option<&str>,
    value: Value,
) -> ToolCallOutput {
    let result_id = srv.results.insert(operation, target_sha256, value.clone());
    output(value, result_id)
}

fn session<'a>(cache: &'a mut Option<(String, Session)>, file: &str) -> Result<&'a Session> {
    // Full session: code tools need recovered code. A cached data-only
    // session for the same file is upgraded in place.
    let stale = cache
        .as_ref()
        .map(|(p, s)| p != file || !s.code_analyzed)
        .unwrap_or(true);
    if stale {
        let sess = Session::open(file, None, ANALYSIS_BUDGET, "the MCP server")?;
        *cache = Some((file.to_string(), sess));
    }
    Ok(&cache.as_ref().expect("just set").1)
}

/// Session for read tools that never touch recovered code. Architectures the
/// engine cannot lift (wasm, MIPS, …) still get their full container view.
fn session_data<'a>(cache: &'a mut Option<(String, Session)>, file: &str) -> Result<&'a Session> {
    let stale = cache.as_ref().map(|(p, _)| p != file).unwrap_or(true);
    if stale {
        let sess = Session::open_data(file, None)?;
        *cache = Some((file.to_string(), sess));
    }
    Ok(&cache.as_ref().expect("just set").1)
}
fn session_mut<'a>(
    cache: &'a mut Option<(String, Session)>,
    file: &str,
) -> Result<&'a mut Session> {
    let stale = cache.as_ref().map(|(p, _)| p != file).unwrap_or(true);
    if stale {
        let sess = Session::open(file, None, ANALYSIS_BUDGET, "the MCP server")?;
        *cache = Some((file.to_string(), sess));
    }
    Ok(&mut cache.as_mut().expect("just set").1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_and_tools_are_well_formed() {
        let init = initialize();
        assert_eq!(init["protocolVersion"], PROTOCOL);
        assert_eq!(init["serverInfo"]["name"], "knife");
        // The handshake orients the client: it must at least say where to begin.
        let guidance = init["instructions"].as_str().unwrap();
        assert!(
            guidance.contains("`open`"),
            "instructions do not name `open`"
        );
        assert!(
            guidance.contains("`audit`"),
            "instructions do not name `audit`"
        );

        let tools = tool_list();
        assert_eq!(tools.len(), 1 + crate::tools::catalog().len());
        assert!(
            tools.len() >= 59,
            "agent surface unexpectedly shrank to {} tools",
            tools.len()
        );
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for want in [
            "open",
            "list_retained_results",
            "get_retained_result",
            "provider_status",
            "yarax_validate_rules",
            "yarax_scan",
            "session_status",
            "list_functions",
            "disassemble",
            "decompile",
            "audit",
            "xrefs",
            "info",
        ] {
            assert!(names.contains(&want), "missing tool {want}");
        }
        // Target operations accept an optional file, while platform-session
        // operations do not pretend to need a binary.
        for t in &tools {
            let name = t["name"].as_str().unwrap();
            assert_eq!(t["inputSchema"]["type"], "object");
            let is_system = matches!(
                name,
                "provider_status"
                    | "yarax_validate_rules"
                    | "list_retained_results"
                    | "get_retained_result"
            );
            assert_eq!(
                t["inputSchema"]["properties"]["file"].is_object(),
                !is_system,
                "wrong target requirement for {name}"
            );
            let req = t["inputSchema"]["required"].as_array().unwrap();
            assert_eq!(
                req.iter().any(|r| r == "file"),
                name == "open",
                "{name} requires `file` when it should not, or the reverse"
            );
            assert!(t["annotations"]["readOnlyHint"].is_boolean());
            assert!(t["_meta"]["knife/access"].is_string());
            if name != "open" {
                assert!(t["_meta"]["knife/targetRequirement"].is_string());
                assert!(t["_meta"]["knife/resultMode"].is_string());
                assert!(t["_meta"]["knife/emitsEvidence"].is_boolean());
            }
        }
        let set_name = tools.iter().find(|t| t["name"] == "set_name").unwrap();
        assert_eq!(set_name["annotations"]["readOnlyHint"], false);
        assert_eq!(set_name["_meta"]["knife/access"], "project_write");
    }

    #[test]
    fn a_bound_target_stands_in_for_the_file_argument() {
        let msg = json!({ "params": { "name": "info", "arguments": {} } });

        // Nothing bound and nothing passed: the error has to say how to bind.
        let mut srv = Server::new(None);
        let e = call_tool(&msg, &mut srv).unwrap_err().to_string();
        assert!(e.contains("no target"), "unhelpful when unbound: {e}");

        // Bound: the same call reaches the file — and fails on the file, which
        // is the point, rather than refusing for want of an argument.
        let mut srv = Server::new(Some("/no/such/file.bin".into()));
        let e = call_tool(&msg, &mut srv).unwrap_err().to_string();
        assert!(!e.contains("no target"), "ignored the bound target: {e}");

        // Naming a file binds it, so the next call need not repeat it.
        let mut srv = Server::new(None);
        let named =
            json!({ "params": { "name": "info", "arguments": { "file": "/no/such/file.bin" } } });
        let _ = call_tool(&named, &mut srv);
        assert_eq!(srv.target.as_deref(), Some("/no/such/file.bin"));
    }

    #[test]
    fn an_unreadable_frame_is_answered_rather_than_dropped() {
        let mut out: Vec<u8> = Vec::new();
        parse_error(&mut out, "frame is not valid JSON").unwrap();
        assert!(
            out.ends_with(
                b"
"
            ),
            "the reply must be its own frame"
        );
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert!(v["id"].is_null(), "an unreadable frame has no known id");
        assert_eq!(v["error"]["code"], -32700);
    }

    #[test]
    fn a_tool_error_is_reported_in_band() {
        // No cached session and a missing file: the call should fail cleanly with
        // an error result rather than panicking.
        let mut srv = Server::new(None);
        let msg = json!({
            "params": { "name": "info", "arguments": { "file": "/no/such/file.bin" } }
        });
        assert!(call_tool(&msg, &mut srv).is_err());
    }

    #[test]
    fn retained_results_are_target_free_and_preserve_structured_content() {
        let mut srv = Server::new(None);
        let id = srv
            .results
            .insert("test", Some("abc"), json!({"answer": 42}))
            .unwrap();
        let msg = json!({
            "params": {
                "name": "get_retained_result",
                "arguments": {"result_id": id.0}
            }
        });
        let output = call_tool(&msg, &mut srv).unwrap();
        assert_eq!(output.structured.as_ref().unwrap()["payload"]["answer"], 42);
        assert!(output.result_id.is_none());
    }
}
