//! The read-tool catalog: one source of truth for every read-only analysis
//! query over a loaded [`Session`].
//!
//! The MCP server (`knife mcp`) exposes this catalog over the same deterministic
//! engine used by CLI/TUI. Each tool takes a `&Session` and returns structured
//! JSON. Full CLI/TUI/MCP query parity remains a separate stabilization task.

use crate::analysis::{
    audit, capabilities, driver, engine, entropy, graphs, hardening, hashes, ir, loldrivers,
    signatures, signing, sinks, strings, triage,
};
use crate::listing::{self, Annot, Line};
use crate::model::SymKind;
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The most rows any single tool returns, so a consumer never has to cope with
/// an unbounded blob from a pathological binary.
pub const ROW_LIMIT: usize = 400;

/// One read-only tool: a name, a one-line description, and its JSON-Schema
/// parameters (without any transport-specific argument such as MCP's `file`).
pub struct ReadTool {
    pub name: &'static str,
    pub description: &'static str,
    /// `{"type":"object","properties":{…},"required":[…]}`.
    pub params: Value,
}

fn tool(
    name: &'static str,
    description: &'static str,
    props: Value,
    required: &[&str],
) -> ReadTool {
    ReadTool {
        name,
        description,
        params: json!({
            "type": "object",
            "properties": props,
            "required": required,
        }),
    }
}

/// Every read tool, in a stable order. This is the list `tools/list` and the
/// agent's tool schema are both built from.
pub fn catalog() -> Vec<ReadTool> {
    vec![
        tool("info", "Format, architecture, entry point, sections, and function/import counts.", json!({}), &[]),
        tool("list_functions", "Recovered functions (address, name, incoming call count), optionally filtered by a name substring.",
             json!({"filter": {"type": "string"}, "limit": {"type": "integer"}, "named_only": {"type": "boolean"}}), &[]),
        tool("disassemble", "Disassembly of one function. selector is a name or hex address.",
             json!({"selector": {"type": "string"}}), &["selector"]),
        tool("decompile", "Decompiled pseudocode for one function.",
             json!({"selector": {"type": "string"}}), &["selector"]),
        tool("audit", "Ranked findings: dangerous call sites whose arguments look exploitable, worst first, with reachability.",
             json!({"limit": {"type": "integer"}}), &[]),
        tool("xrefs", "What references (calls/jumps to) an address or function — the callers.",
             json!({"selector": {"type": "string"}}), &["selector"]),
        tool("callees", "What one function calls — the outgoing calls, resolved to names.",
             json!({"selector": {"type": "string"}}), &["selector"]),
        tool("paths_to", "Call chains that reach a function from the entry point or an export.",
             json!({"selector": {"type": "string"}}), &["selector"]),
        tool("trace_taint", "For one function, the exploitable-looking sinks it contains with each dangerous argument's provenance, plus the call chains that reach the function — how caller-controlled input flows to a dangerous call.",
             json!({"selector": {"type": "string"}}), &["selector"]),
        tool("strings", "String literals whose text contains a query (empty query lists the first strings), with reference counts.",
             json!({"query": {"type": "string"}, "limit": {"type": "integer"}}), &[]),
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
             json!({"selector": {"type": "string"}}), &["selector"]),
        tool("sinks", "Dangerous-API call sites (the raw attack surface, by class), before ranking.", json!({}), &[]),
        tool("signatures", "Byte-signature hits: crypto constants, packers, and embedded formats.", json!({}), &[]),
        tool("loldrivers", "Whether this file's sha256 matches a known vulnerable/malicious driver (LOLDrivers).", json!({}), &[]),
        tool("read_bytes", "A hex+ascii dump at a virtual address.",
             json!({"address": {"type": "string"}, "length": {"type": "integer"}}), &["address"]),
    ]
}

/// Tools whose answers come from recovered code rather than container facts.
/// The MCP server opens these against a code-analyzed session; everything else
/// also works on architectures without a lifter (wasm, MIPS, …).
pub fn needs_code(name: &str) -> bool {
    matches!(
        name,
        "list_functions"
            | "disassemble"
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
        "info" => Ok(info(sess)),
        "list_functions" => Ok(list_functions(sess, args)),
        "disassemble" => Ok(json!(disassemble(sess, &sel(args)?)?)),
        "decompile" => Ok(json!(decompile(sess, &sel(args)?)?)),
        "audit" => Ok(run_audit(sess, args)),
        "xrefs" => callers(sess, &sel(args)?),
        "callees" => callees(sess, &sel(args)?),
        "paths_to" => paths_to(sess, &sel(args)?),
        "trace_taint" => trace_taint(sess, &sel(args)?),
        "strings" => Ok(strings_tool(sess, args)),
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
        other => Err(anyhow!("unknown tool '{other}'")),
    }
}

// ── argument + resolution helpers ──────────────────────────────────────────

fn sel(args: &Value) -> Result<String> {
    args.get("selector")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("missing `selector`"))
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

fn list_functions(sess: &Session, args: &Value) -> Value {
    let needle = args
        .get("filter")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let named_only = args
        .get("named_only")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(200)
        .min(ROW_LIMIT);
    let rows: Vec<Value> = sess
        .an
        .functions
        .iter()
        .filter(|f| !named_only || f.named)
        .filter(|f| needle.is_empty() || f.name.to_lowercase().contains(&needle))
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
    json!({ "count": sess.an.functions.len(), "functions": rows })
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

fn strings_tool(sess: &Session, args: &Value) -> Value {
    let q = args
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(80)
        .min(ROW_LIMIT);
    let base = engine::display_base(&sess.bin);
    let string_map = listing::string_map(&sess.bin, &sess.bytes, base);
    let rows: Vec<Value> = string_map
        .iter()
        .filter(|(_, st)| q.is_empty() || st.text.to_lowercase().contains(&q))
        .take(limit)
        .map(|(addr, st)| json!({ "addr": format!("0x{addr:x}"), "refs": sess.an.xrefs_to.get(addr).map_or(0, Vec::len), "text": st.text }))
        .collect();
    json!({ "count": rows.len(), "strings": rows })
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
    let base = engine::display_base(&sess.bin);
    let lines = listing::data_view(&sess.bin, base, &sess.bytes, addr);
    if lines.is_empty() {
        return Err(anyhow!("no mapped data at {a}"));
    }
    Ok(lines
        .iter()
        .take(ROW_LIMIT)
        .map(|l| render_line(l, base))
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
        for t in catalog() {
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
