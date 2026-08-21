//! The command console.
//!
//! The verbs mirror the command line's, so what someone already knows about
//! `knife` transfers straight over: this is a second way to reach the same
//! engine calls, not a second implementation of them. Everything runs against
//! the target already open in the window.

use crate::commands::{parse_addr, resolve, site_name};
use crate::dto::{hex, ConsoleLine};
use crate::state::AppState;
use anyhow::anyhow;
use reknife::analysis::ir;
use reknife::listing;
use tauri::State;

const HELP: &[(&str, &str)] = &[
    ("info", "format, architecture, entry, counts, verdict"),
    ("funcs [query]", "recovered functions, filtered by name"),
    ("audit [n]", "ranked sink call sites, worst first"),
    ("strings <query>", "literals whose text matches"),
    ("xrefs <sel>", "what references a function or address"),
    ("dis <sel> [n]", "disassembly, first n lines"),
    ("pseudo <sel>", "decompiled pseudocode"),
    ("sections", "the section table"),
    ("clear", "empty the scrollback"),
];

/// Run one console command against the open target.
#[tauri::command]
pub fn console_exec(state: State<AppState>, line: String) -> Result<Vec<ConsoleLine>, String> {
    let line = line.trim().to_string();
    if line.is_empty() {
        return Ok(Vec::new());
    }
    let (verb, rest) = match line.split_once(char::is_whitespace) {
        Some((v, r)) => (v, r.trim()),
        None => (line.as_str(), ""),
    };

    if verb == "help" || verb == "?" {
        let mut out = vec![ConsoleLine::hint("commands:")];
        for (name, what) in HELP {
            out.push(ConsoleLine::out(format!("  {name:<18} {what}")));
        }
        return Ok(out);
    }

    state
        .read(|l| {
            let an = &l.session.an;
            let mut out: Vec<ConsoleLine> = Vec::new();
            match verb {
                "info" => {
                    let b = &l.session.bin;
                    out.push(ConsoleLine::out(format!(
                        "{}  {}  {}-bit  ·  {} sections  ·  entry {}",
                        b.format.label(),
                        b.arch.label(),
                        b.bits,
                        b.sections.len(),
                        hex(b.entry),
                    )));
                    out.push(ConsoleLine::out(format!(
                        "{} functions, {} named  ·  {} findings ({} high-risk)",
                        an.functions.len(),
                        an.functions.iter().filter(|f| f.named).count(),
                        l.findings.len(),
                        l.findings.iter().filter(|f| f.severity >= 3).count(),
                    )));
                    if an.truncated {
                        out.push(ConsoleLine::hint(
                            "analysis budget reached: recovery is partial",
                        ));
                    }
                }
                "sections" => {
                    for s in &l.session.bin.sections {
                        out.push(ConsoleLine::out(format!(
                            "  {:<12} {:>12}  {:>10} bytes  {}  entropy {:.2}",
                            s.name,
                            hex(s.vaddr),
                            s.vsize,
                            s.flags(),
                            s.entropy,
                        )));
                    }
                }
                "funcs" => {
                    let needle = rest.to_lowercase();
                    let mut shown = 0;
                    for f in an
                        .functions
                        .iter()
                        .filter(|f| needle.is_empty() || f.name.to_lowercase().contains(&needle))
                    {
                        if shown >= 100 {
                            out.push(ConsoleLine::hint("… more matches, narrow the query"));
                            break;
                        }
                        out.push(ConsoleLine::out(format!(
                            "  {:>12}  {:<44} {:>4} refs",
                            hex(f.addr),
                            f.name,
                            f.incoming
                        )));
                        shown += 1;
                    }
                    if shown == 0 {
                        out.push(ConsoleLine::hint("no function matches"));
                    }
                }
                "audit" => {
                    let limit: usize = rest.parse().unwrap_or(30);
                    for f in l.findings.iter().take(limit) {
                        let mark = if f.severity >= 3 {
                            "[H]"
                        } else if f.severity >= 2 {
                            "[M]"
                        } else {
                            "[L]"
                        };
                        out.push(ConsoleLine::out(format!(
                            "  {mark} {:<16} {:<12} {:>12}  {}",
                            f.pattern,
                            f.api,
                            hex(f.addr),
                            f.func.as_deref().unwrap_or("-")
                        )));
                    }
                    if l.findings.is_empty() {
                        out.push(ConsoleLine::hint("no findings"));
                    }
                }
                "strings" => {
                    if rest.is_empty() {
                        return Ok(vec![ConsoleLine::err("usage: strings <query>")]);
                    }
                    let needle = rest.to_lowercase();
                    let mut shown = 0;
                    for (addr, s) in l.strings.iter() {
                        if !s.text.to_lowercase().contains(&needle) {
                            continue;
                        }
                        if shown >= 100 {
                            out.push(ConsoleLine::hint("… more matches, narrow the query"));
                            break;
                        }
                        let refs = an.xrefs_to.get(addr).map_or(0, Vec::len);
                        out.push(ConsoleLine::out(format!(
                            "  {:>12}  {:>3} refs  {:?}",
                            hex(*addr),
                            refs,
                            s.text
                        )));
                        shown += 1;
                    }
                    if shown == 0 {
                        out.push(ConsoleLine::hint("no literal matches"));
                    }
                }
                "xrefs" => {
                    if rest.is_empty() {
                        return Ok(vec![ConsoleLine::err("usage: xrefs <name|address>")]);
                    }
                    let target = resolve(an, rest)
                        .map(|f| f.addr)
                        .or_else(|| parse_addr(rest).ok())
                        .ok_or_else(|| anyhow!("nothing matches {rest:?}"))?;
                    match an.xrefs_to.get(&target) {
                        Some(refs) => {
                            for x in refs {
                                out.push(ConsoleLine::out(format!(
                                    "  {:>12}  {:<7} {}",
                                    hex(x.from),
                                    x.kind.label(),
                                    site_name(an, x.from)
                                )));
                            }
                        }
                        None => out.push(ConsoleLine::hint("no references")),
                    }
                }
                "dis" => {
                    // `dis <sel> [n]`: a trailing number is the line count.
                    let (sel, count) = match rest.rsplit_once(char::is_whitespace) {
                        Some((s, n)) if n.parse::<usize>().is_ok() => {
                            (s.trim(), n.parse().unwrap_or(40))
                        }
                        _ => (rest, 40usize),
                    };
                    let f = resolve(an, sel).ok_or_else(|| anyhow!("nothing matches {sel:?}"))?;
                    let lines = listing::function(
                        an,
                        f,
                        &l.session.db,
                        l.base,
                        &l.strings,
                        l.hints.as_ref(),
                    );
                    for line in lines.iter().take(count) {
                        out.push(ConsoleLine::out(match line {
                            listing::Line::Label { text, .. } => format!("  {text}"),
                            listing::Line::Insn {
                                addr,
                                mnemonic,
                                operands,
                                ..
                            } => format!("  {:>12}  {:<7} {}", hex(*addr), mnemonic, operands),
                            listing::Line::Data { addr, text } => {
                                format!("  {:>12}  {}", hex(*addr), text)
                            }
                        }));
                    }
                }
                "pseudo" => {
                    let f = resolve(an, rest).ok_or_else(|| anyhow!("nothing matches {rest:?}"))?;
                    for line in ir::decompile(an, &l.session.bin, f, &l.strings, &l.session.db) {
                        out.push(ConsoleLine::out(line.text));
                    }
                }
                other => {
                    out.push(ConsoleLine::err(format!(
                        "unknown command {other:?} — try `help`"
                    )));
                }
            }
            Ok(out)
        })
        .map_err(|e| e.to_string())
}
