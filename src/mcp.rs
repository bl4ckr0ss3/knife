//! A Model Context Protocol server (`knife mcp`): a JSON-RPC 2.0 stream over
//! stdio that exposes the analysis as tools, so an agent (ARGUS, or any MCP
//! client) can drive knife directly. It reuses the same engine, listing,
//! decompiler, and audit the command line does; only the wire format is new.
//!
//! The stdio transport is newline-delimited JSON: one message per line, nothing
//! else on stdout (logs go to stderr), so the stream stays clean.

use crate::analysis::{audit, engine, ir};
use crate::listing::{self, Annot, Line};
use crate::{workspace::Session, ANALYSIS_BUDGET};
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL: &str = "2024-11-05";

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

/// Run the server until stdin closes.
pub fn run() -> Result<()> {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut out = std::io::stdout();
    // The last file analysed, cached so repeated tool calls on one target do not
    // re-run the whole engine each time.
    let mut cache: Option<(String, Session)> = None;

    while let Some(frame) = read_frame(&mut reader)? {
        if frame.len() >= MAX_FRAME {
            continue; // oversized frame: drain-and-drop, fail closed
        }
        let line = String::from_utf8_lossy(&frame);
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue; // not JSON: ignore rather than crash the stream
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
            "tools/call" => match call_tool(&msg, &mut cache) {
                Ok(text) => ok(id.clone(), tool_text(&text, false)),
                Err(e) => ok(id.clone(), tool_text(&format!("error: {e:#}"), true)),
            },
            _ => err(id.clone(), -32601, "method not found"),
        }))
        .unwrap_or_else(|_| {
            cache = None; // drop any state a panic may have poisoned
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

fn err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_text(text: &str, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "knife", "version": env!("CARGO_PKG_VERSION") },
    })
}

fn file_arg() -> Value {
    json!({ "type": "string", "description": "path to the binary" })
}

fn tool_list() -> Vec<Value> {
    let file_only = json!({
        "type": "object",
        "properties": { "file": file_arg() },
        "required": ["file"],
    });
    let file_func = json!({
        "type": "object",
        "properties": {
            "file": file_arg(),
            "function": { "type": "string", "description": "function name or address (0x...)" },
        },
        "required": ["file", "function"],
    });
    vec![
        tool(
            "list_functions",
            "List the recovered functions (address, name, block count, incoming references).",
            json!({
                "type": "object",
                "properties": {
                    "file": file_arg(),
                    "limit": { "type": "number", "description": "max functions (default 200)" },
                    "named_only": { "type": "boolean", "description": "only named functions" },
                },
                "required": ["file"],
            }),
        ),
        tool(
            "disassemble",
            "Disassemble one function, with resolved call names and string annotations.",
            file_func.clone(),
        ),
        tool(
            "decompile",
            "Decompile one function to structured pseudocode (if/else/while/switch, named locals, inlined strings).",
            file_func,
        ),
        tool(
            "audit",
            "Rank the sink call sites by how exploitable their arguments look (argument-provenance bug finder).",
            file_only.clone(),
        ),
        tool(
            "xrefs",
            "List the cross-references to an address.",
            json!({
                "type": "object",
                "properties": {
                    "file": file_arg(),
                    "address": { "type": "string", "description": "target address (0x...)" },
                },
                "required": ["file", "address"],
            }),
        ),
        tool(
            "info",
            "Summarise the file: format, architecture, sections, imports, function count.",
            file_only,
        ),
    ]
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": schema })
}

fn call_tool(msg: &Value, cache: &mut Option<(String, Session)>) -> Result<String> {
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing tool name"))?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let file = args
        .get("file")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing `file`"))?
        .to_string();

    let sess = session(cache, &file)?;
    match name {
        "list_functions" => Ok(list_functions(sess, &args)),
        "disassemble" => with_func(sess, &args, disassemble),
        "decompile" => with_func(sess, &args, decompile),
        "audit" => Ok(run_audit(sess)),
        "xrefs" => xrefs(sess, &args),
        "info" => Ok(info(sess)),
        other => anyhow::bail!("unknown tool '{other}'"),
    }
}

/// Load and analyse `file`, reusing the cached session when it is the same file.
fn session<'a>(cache: &'a mut Option<(String, Session)>, file: &str) -> Result<&'a Session> {
    let stale = cache.as_ref().map(|(p, _)| p != file).unwrap_or(true);
    if stale {
        let sess = Session::open(file, None, ANALYSIS_BUDGET, "the MCP server")?;
        *cache = Some((file.to_string(), sess));
    }
    Ok(&cache.as_ref().expect("just set").1)
}

fn resolve<'a>(an: &'a engine::Analysis, sel: &str) -> Option<&'a engine::Function> {
    if let Some(f) = an.find_by_name(sel) {
        return Some(f);
    }
    let hex = sel.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16)
        .ok()
        .and_then(|a| an.find_function(a).or_else(|| an.function_at(a)))
}

fn with_func(
    sess: &Session,
    args: &Value,
    f: impl Fn(&Session, &engine::Function) -> String,
) -> Result<String> {
    let sel = args
        .get("function")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing `function`"))?;
    let func = resolve(&sess.an, sel)
        .ok_or_else(|| anyhow::anyhow!("no function '{sel}' (try list_functions)"))?;
    Ok(f(sess, func))
}

fn list_functions(sess: &Session, args: &Value) -> String {
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
    let named_only = args
        .get("named_only")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let rows: Vec<Value> = sess
        .an
        .functions
        .iter()
        .filter(|f| !named_only || f.named)
        .take(limit)
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
    json!({ "count": sess.an.functions.len(), "functions": rows }).to_string()
}

fn decompile(sess: &Session, f: &engine::Function) -> String {
    let base = engine::display_base(&sess.bin);
    let strings = listing::string_map(&sess.bin, &sess.bytes, base);
    ir::decompile(&sess.an, &sess.bin, f, &strings, &sess.db)
        .into_iter()
        .map(|l| l.text)
        .collect::<Vec<_>>()
        .join("\n")
}

fn disassemble(sess: &Session, f: &engine::Function) -> String {
    let base = engine::display_base(&sess.bin);
    let strings = listing::string_map(&sess.bin, &sess.bytes, base);
    let hints = if crate::analysis::driver::plausibly_a_driver(&sess.bin) {
        crate::analysis::driver::listing_hints(&sess.bin, &sess.bytes, &sess.an)
    } else {
        std::collections::BTreeMap::new()
    };
    listing::function(&sess.an, f, &sess.db, base, &strings, Some(&hints))
        .iter()
        .map(|l| render_line(l, base))
        .collect::<Vec<_>>()
        .join("\n")
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

fn run_audit(sess: &Session) -> String {
    let mut findings = audit::run(&sess.an, &sess.bin, &sess.bytes);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.addr.cmp(&b.addr)));
    let rows: Vec<Value> = findings
        .iter()
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
    json!({ "count": rows.len(), "findings": rows }).to_string()
}

fn xrefs(sess: &Session, args: &Value) -> Result<String> {
    let sel = args
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing `address`"))?;
    let hex = sel.trim().trim_start_matches("0x").trim_start_matches("0X");
    let at = u64::from_str_radix(hex, 16).map_err(|_| anyhow::anyhow!("bad address '{sel}'"))?;
    let rows: Vec<Value> = sess
        .an
        .xrefs_to
        .get(&at)
        .map(|v| {
            v.iter()
                .map(|x| {
                    let site = sess
                        .an
                        .function_at(x.from)
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| "-".into());
                    json!({ "from": format!("0x{:x}", x.from), "kind": x.kind.label(), "in": site })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({ "to": format!("0x{at:x}"), "count": rows.len(), "xrefs": rows }).to_string())
}

fn info(sess: &Session) -> String {
    let named = sess.an.functions.iter().filter(|f| f.named).count();
    json!({
        "format": sess.bin.format.label(),
        "arch": sess.bin.arch.label(),
        "sections": sess.bin.sections.iter().map(|s| &s.name).collect::<Vec<_>>(),
        "imports": sess.an.imports.len(),
        "functions": sess.an.functions.len(),
        "named_functions": named,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_and_tools_are_well_formed() {
        let init = initialize();
        assert_eq!(init["protocolVersion"], PROTOCOL);
        assert_eq!(init["serverInfo"]["name"], "knife");

        let tools = tool_list();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for want in [
            "list_functions",
            "disassemble",
            "decompile",
            "audit",
            "xrefs",
            "info",
        ] {
            assert!(names.contains(&want), "missing tool {want}");
        }
        // Every tool advertises an object input schema requiring a file.
        for t in &tools {
            assert_eq!(t["inputSchema"]["type"], "object");
            let req = t["inputSchema"]["required"].as_array().unwrap();
            assert!(req.iter().any(|r| r == "file"));
        }
    }

    #[test]
    fn a_tool_error_is_reported_in_band() {
        // No cached session and a missing file: the call should fail cleanly with
        // an error result rather than panicking.
        let mut cache = None;
        let msg = json!({
            "params": { "name": "info", "arguments": { "file": "/no/such/file.bin" } }
        });
        assert!(call_tool(&msg, &mut cache).is_err());
    }
}
