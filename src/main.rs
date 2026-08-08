//! knife — a reverse engineer's binary Swiss-army knife.
//!
//! Parse, triage, and disassemble PE / ELF / Mach-O. One binary, no runtime.

mod analysis;
mod formats;
mod model;
mod output;

use analysis::{capabilities, disasm, engine, hashes, signatures, strings as strs, triage, yara};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use model::Binary;
use output::*;
use owo_colors::{OwoColorize, Style};
use serde_json::json;

#[derive(Parser)]
#[command(
    name = "knife",
    version,
    about = "A reverse engineer's binary Swiss-army knife (PE / ELF / Mach-O)",
    disable_help_subcommand = true
)]
struct Cli {
    /// Emit machine-readable JSON instead of the terminal report.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Full triage report (default).
    Info {
        file: String,
        /// Also run YARA rules (a .yar/.yara file or a directory) and fold
        /// matches into the verdict.
        #[arg(long)]
        rules: Option<String>,
    },
    /// List sections/segments with entropy.
    Sections { file: String },
    /// List imported libraries and functions.
    Imports { file: String },
    /// List exported symbols.
    Exports { file: String },
    /// Capabilities inferred from imports/symbols.
    Caps { file: String },
    /// Extract printable strings.
    Strings {
        file: String,
        #[arg(long, default_value_t = 5)]
        min: usize,
    },
    /// Extract indicators of compromise (defanged).
    Iocs { file: String },
    /// File hashes and imphash.
    Hashes { file: String },
    /// Disassemble (x86/x64) from the entry point, a location, or a function.
    Dis {
        file: String,
        #[arg(long, default_value_t = 40)]
        count: usize,
        /// Virtual address to start at (default: entry point).
        #[arg(long)]
        vaddr: Option<String>,
        /// File offset to start at.
        #[arg(long)]
        off: Option<String>,
        /// Disassemble a whole recovered function by name or address.
        #[arg(long)]
        func: Option<String>,
    },
    /// Recover and list functions (control-flow analysis, x86/x64).
    Funcs {
        file: String,
        /// Sort by incoming references instead of address.
        #[arg(long)]
        by_refs: bool,
    },
    /// Hex dump a range.
    Hex {
        file: String,
        #[arg(long, default_value_t = 0)]
        off: u64,
        #[arg(long, default_value_t = 256)]
        len: usize,
    },
    /// Whole-file entropy map.
    Map {
        file: String,
        #[arg(long, default_value_t = 64)]
        buckets: usize,
    },
    /// Scan for crypto constants, packer markers, and embedded formats.
    Scan { file: String },
    /// Match YARA rules against a file (rules = a .yar/.yara file or a directory).
    Yara { rules: String, file: String },
    /// List archive (.a/.lib) members.
    Ls { file: String },
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("{} {:#}", "error:".style(red()).bold(), e);
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    // Allow `knife <file>` as shorthand for `knife info <file>`.
    let mut args: Vec<String> = std::env::args().collect();
    let known = [
        "info",
        "sections",
        "imports",
        "exports",
        "caps",
        "strings",
        "iocs",
        "hashes",
        "dis",
        "hex",
        "map",
        "scan",
        "yara",
        "funcs",
        "ls",
        "help",
        "-h",
        "--help",
        "-V",
        "--version",
    ];
    if args.len() >= 2 && !known.contains(&args[1].as_str()) && !args[1].starts_with('-') {
        args.insert(1, "info".into());
    }

    let cli = Cli::parse_from(args);
    match cli.cmd {
        Command::Info { file, rules } => cmd_info(&file, rules.as_deref(), cli.json),
        Command::Sections { file } => cmd_sections(&file, cli.json),
        Command::Imports { file } => cmd_imports(&file, cli.json),
        Command::Exports { file } => cmd_exports(&file, cli.json),
        Command::Caps { file } => cmd_caps(&file, cli.json),
        Command::Strings { file, min } => cmd_strings(&file, min, cli.json),
        Command::Iocs { file } => cmd_iocs(&file, cli.json),
        Command::Hashes { file } => cmd_hashes(&file, cli.json),
        Command::Dis {
            file,
            count,
            vaddr,
            off,
            func,
        } => cmd_dis(&file, count, vaddr, off, func),
        Command::Funcs { file, by_refs } => cmd_funcs(&file, by_refs, cli.json),
        Command::Hex { file, off, len } => cmd_hex(&file, off, len),
        Command::Map { file, buckets } => cmd_map(&file, buckets, cli.json),
        Command::Scan { file } => cmd_scan(&file, cli.json),
        Command::Yara { rules, file } => cmd_yara(&rules, &file, cli.json),
        Command::Ls { file } => cmd_ls(&file),
    }
}

fn load(file: &str) -> Result<Vec<u8>> {
    std::fs::read(file).with_context(|| format!("cannot read {file}"))
}

fn parse(file: &str, bytes: &[u8]) -> Result<Binary> {
    formats::analyze(file, bytes)
}

// ── info ─────────────────────────────────────────────────────────────────

fn cmd_info(file: &str, rules: Option<&str>, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    let all_syms: Vec<&str> = bin
        .all_imported_functions()
        .chain(bin.exports.iter().map(String::as_str))
        .collect();
    let caps = capabilities::matches(all_syms.into_iter());
    let cluster = capabilities::cluster(&caps);

    // Optional YARA pass folded into the verdict.
    let yara_matches = match rules {
        Some(path) => {
            let (compiled, _) = yara::compile(path)?;
            yara::scan(&compiled, &bytes)?
        }
        None => Vec::new(),
    };
    let yara_names: Vec<String> = yara_matches.iter().map(|m| m.rule.clone()).collect();
    let tri = triage::run(&bin, &caps, &yara_names);
    let fh = hashes::file_hashes(&bytes);
    let imphash = hashes::imphash(&bin);
    let all_strings = strs::extract(&bytes, 5);
    let iocs = strs::find_iocs(&all_strings);

    if as_json {
        let out = json!({
            "file": bin.path,
            "format": bin.format.label(),
            "arch": bin.arch.label(),
            "bits": bin.bits,
            "size": bin.size,
            "is_lib": bin.is_lib,
            "stripped": bin.is_stripped,
            "entry": bin.entry,
            "image_base": bin.image_base,
            "subsystem": bin.subsystem,
            "overall_entropy": bin.overall_entropy,
            "overlay": bin.overlay_off.map(|o| json!({"off": o, "size": bin.overlay_size, "entropy": bin.overlay_entropy})),
            "has_signature": bin.has_signature,
            "md5": fh.md5, "sha1": fh.sha1, "sha256": fh.sha256, "imphash": imphash,
            "sections": bin.sections,
            "imports": bin.imports,
            "exports_count": bin.exports.len(),
            "libs": bin.libs,
            "capabilities": cluster,
            "iocs": iocs,
            "verdict": tri.verdict,
            "score": tri.score,
            "signals": tri.signals,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    // header
    println!();
    println!("  {}", basename(&bin.path).style(accent()).bold());
    let kind = format!(
        "{} · {} · {}{} · {}",
        bin.format.label(),
        bin.arch.label(),
        if bin.is_lib { "library" } else { "program" },
        if bin.is_stripped { " · stripped" } else { "" },
        bin.notes.join(", ")
    );
    println!("  {}", kind.style(muted()));

    verdict_banner(&tri);

    section_header("file");
    kv("size", human(bin.size));
    kv("entropy", format!("{:.2} / 8", bin.overall_entropy));
    if let Some(sub) = &bin.subsystem {
        kv("subsystem", sub);
    }
    kv("entry", format!("0x{:x}", bin.entry));
    if bin.image_base != 0 {
        kv("imagebase", format!("0x{:x}", bin.image_base));
    }
    kv("md5", fh.md5);
    kv("sha256", fh.sha256);
    if let Some(ih) = &imphash {
        kv("imphash", ih);
    }
    if let Some(off) = bin.overlay_off {
        kv_styled(
            "overlay",
            format!(
                "{} @ 0x{:x}  H={:.2}",
                human(bin.overlay_size),
                off,
                bin.overlay_entropy
            ),
            if bin.overlay_entropy >= 7.2 {
                red()
            } else {
                muted()
            },
        );
    }

    // signals
    section_header("signals");
    if tri.signals.is_empty() {
        println!("  {}", "no notable static signals".style(faint()));
    }
    for s in &tri.signals {
        let w = if s.weight != 0 {
            format!(" {:+}", s.weight)
        } else {
            String::new()
        };
        println!(
            "  {} {}{}",
            marker(s.kind).style(kind_style(s.kind)),
            s.text,
            w.style(faint())
        );
    }

    // sections
    print_sections(&bin);

    // capabilities
    if !caps.is_empty() {
        section_header("capabilities");
        let line: Vec<String> = cluster.iter().map(|(k, v)| format!("{k} ×{v}")).collect();
        println!("  {}", line.join("   ").style(amber()));
        for m in caps.iter().take(10) {
            let st = if m.weight >= 3 { red() } else { amber() };
            println!(
                "  {:<26} {}",
                m.api.style(st),
                format!("{} · {}", m.category, m.why).style(faint())
            );
        }
        if caps.len() > 10 {
            println!(
                "  {}",
                format!("… and {} more", caps.len() - 10).style(faint())
            );
        }
    }

    // iocs
    if !iocs.is_empty() {
        section_header(&format!("indicators ({}) — defanged", iocs.len()));
        for i in iocs.iter().take(20) {
            println!(
                "  {:<8} {}",
                i.kind.style(faint()),
                strs::defang(&i.kind, &i.value)
            );
        }
        if iocs.len() > 20 {
            println!(
                "  {}",
                format!("… and {} more", iocs.len() - 20).style(faint())
            );
        }
    }

    // YARA matches (only when --rules was given)
    if !yara_matches.is_empty() {
        section_header(&format!("yara ({})", yara_matches.len()));
        for m in &yara_matches {
            print_yara_match(m);
        }
    }

    // crypto / packer / embedded artifacts
    let hits = signatures::scan(&bin, &bytes);
    if !hits.is_empty() {
        section_header(&format!("artifacts ({})", hits.len()));
        // one line per distinct signature name, with a count
        let mut seen = std::collections::BTreeMap::<&str, (usize, &str)>::new();
        for h in &hits {
            let e = seen
                .entry(h.name.as_str())
                .or_insert((0, h.category.as_str()));
            e.0 += 1;
        }
        for (name, (count, cat)) in &seen {
            let (st, kind) = match *cat {
                "packer" => (red(), "bad"), // packers genuinely warrant suspicion
                "crypto" | "hash" => (amber(), "warn"),
                _ => (mint(), "info"), // embedded formats are informational
            };
            let c = if *count > 1 {
                format!(" ×{count}")
            } else {
                String::new()
            };
            println!(
                "  {} {}{}",
                marker(kind).style(st),
                name.style(st),
                c.style(faint())
            );
        }
        println!("  {}", "run `knife scan` for offsets".style(faint()));
    }

    // disasm teaser
    if disasm::supported(bin.arch) {
        if let Some((off, va)) = disasm::entry_location(&bin, &bytes) {
            section_header("entry point");
            let insns = disasm::disassemble(&bytes, off, va, bin.bits, 8);
            print_disasm(&insns);
            println!("  {}", "run `knife dis` for more".style(faint()));
        }
    }

    println!();
    println!(
        "  {}",
        format!(
            "{} sections · {} imports · {} strings · {} IOCs",
            bin.sections.len(),
            bin.all_imported_functions().count(),
            all_strings.len(),
            iocs.len()
        )
        .style(faint())
    );
    Ok(())
}

// ── sub-commands ──────────────────────────────────────────────────────────

fn print_sections(bin: &Binary) {
    section_header("sections");
    println!(
        "  {:<20} {:<5} {:>10} {:>10}  {:<24} {}",
        "name".style(faint()),
        "flags".style(faint()),
        "vsize".style(faint()),
        "rawsize".style(faint()),
        "entropy".style(faint()),
        "".style(faint())
    );
    for s in &bin.sections {
        let name_style = if s.is_wx() { red() } else { Style::new() };
        let est = entropy_style(s.entropy);
        println!(
            "  {:<20} {:<5} {:>10} {:>10}  {} {}",
            truncate(&s.name, 20).style(name_style),
            s.flags(),
            s.vsize,
            s.file_size,
            entropy_bar(s.entropy, 20).style(est),
            format!("{:.2}", s.entropy).style(est),
        );
    }
}

fn cmd_sections(file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&bin.sections)?);
    } else {
        print_sections(&bin);
    }
    Ok(())
}

fn cmd_imports(file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&bin.imports)?);
        return Ok(());
    }
    let flagged: std::collections::HashMap<&str, &capabilities::ApiFlag> =
        capabilities::CATALOG.iter().map(|f| (f.api, f)).collect();
    for lib in &bin.imports {
        section_header(&format!("{} ({})", lib.name, lib.functions.len()));
        for f in &lib.functions {
            let bare = f.strip_prefix('_').unwrap_or(f);
            if let Some(fl) = flagged.get(bare) {
                let st = if fl.weight >= 3 { red() } else { amber() };
                println!(
                    "  {:<28} {}",
                    f.style(st),
                    format!("← {}: {}", fl.category, fl.why).style(faint())
                );
            } else {
                println!("  {}", f.style(muted()));
            }
        }
    }
    Ok(())
}

fn cmd_exports(file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&bin.exports)?);
        return Ok(());
    }
    section_header(&format!("exports ({})", bin.exports.len()));
    for e in &bin.exports {
        println!("  {}", e.style(muted()));
    }
    Ok(())
}

fn cmd_caps(file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    let syms: Vec<&str> = bin
        .all_imported_functions()
        .chain(bin.exports.iter().map(String::as_str))
        .collect();
    let caps = capabilities::matches(syms.into_iter());
    let cluster = capabilities::cluster(&caps);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"clusters": cluster}))?
        );
        return Ok(());
    }
    section_header("capabilities");
    if caps.is_empty() {
        println!("  {}", "none from the catalogue".style(faint()));
        return Ok(());
    }
    let line: Vec<String> = cluster.iter().map(|(k, v)| format!("{k} ×{v}")).collect();
    println!("  {}", line.join("   ").style(amber()));
    println!();
    for m in &caps {
        let st = if m.weight >= 3 { red() } else { amber() };
        println!(
            "  {:<26} {}",
            m.api.style(st),
            format!("{} · {}", m.category, m.why).style(faint())
        );
    }
    Ok(())
}

fn cmd_strings(file: &str, min: usize, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let out = strs::extract(&bytes, min);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for s in &out {
            println!("{s}");
        }
    }
    Ok(())
}

fn cmd_iocs(file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let all = strs::extract(&bytes, 5);
    let iocs = strs::find_iocs(&all);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&iocs)?);
        return Ok(());
    }
    section_header(&format!("indicators ({}) — defanged", iocs.len()));
    for i in &iocs {
        println!(
            "  {:<8} {}",
            i.kind.style(faint()),
            strs::defang(&i.kind, &i.value)
        );
    }
    Ok(())
}

fn cmd_hashes(file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes).ok();
    let fh = hashes::file_hashes(&bytes);
    let imphash = bin.as_ref().and_then(hashes::imphash);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "md5": fh.md5, "sha1": fh.sha1, "sha256": fh.sha256, "imphash": imphash
            }))?
        );
        return Ok(());
    }
    section_header("hashes");
    kv("md5", fh.md5);
    kv("sha1", fh.sha1);
    kv("sha256", fh.sha256);
    if let Some(ih) = imphash {
        kv("imphash", ih);
    }
    Ok(())
}

fn print_disasm(insns: &[disasm::Insn]) {
    for i in insns {
        let raw: String = i
            .bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let (mn, rest) = i.text.split_once(' ').unwrap_or((i.text.as_str(), ""));
        println!(
            "  {}  {:<20} {} {}",
            format!("{:012x}", i.addr).style(faint()),
            raw.style(faint()),
            mn.style(accent()),
            rest.style(muted()),
        );
    }
}

fn cmd_dis(
    file: &str,
    count: usize,
    vaddr: Option<String>,
    off: Option<String>,
    func: Option<String>,
) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    if !disasm::supported(bin.arch) {
        anyhow::bail!(
            "disassembly supports x86/x64 only; this is {}",
            bin.arch.label()
        );
    }

    // Function mode: recover the CFG and print the whole function with labels,
    // resolved call targets, and cross-references.
    if let Some(sel) = func {
        return dis_function(&bin, &bytes, &sel);
    }

    let (foff, va) = if let Some(o) = off {
        let o = parse_num(&o)?;
        (o, o)
    } else if let Some(v) = vaddr {
        let v = parse_num(&v)?;
        (
            disasm::vaddr_to_off(&bin, v).context("vaddr not in any section")?,
            v,
        )
    } else {
        disasm::entry_location(&bin, &bytes).context("cannot locate entry point")?
    };
    section_header(&format!("disassembly @ 0x{va:x}"));
    let insns = disasm::disassemble(&bytes, foff, va, bin.bits, count);
    print_disasm(&insns);
    Ok(())
}

fn cmd_funcs(file: &str, by_refs: bool, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    if !disasm::supported(bin.arch) {
        anyhow::bail!(
            "control-flow analysis supports x86/x64 only; this is {}",
            bin.arch.label()
        );
    }
    let an = engine::analyze(&bin, &bytes, 500_000);

    let mut funcs: Vec<&engine::Function> = an.functions.iter().collect();
    if by_refs {
        funcs.sort_by(|a, b| b.incoming.cmp(&a.incoming).then(a.addr.cmp(&b.addr)));
    }

    if as_json {
        let rows: Vec<_> = funcs
            .iter()
            .map(|f| {
                serde_json::json!({
                    "addr": f.addr + an.display_base,
                    "name": f.name,
                    "named": f.named,
                    "blocks": f.blocks.len(),
                    "size": f.size,
                    "incoming": f.incoming,
                    "calls": f.calls.len(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    let named = funcs.iter().filter(|f| f.named).count();
    section_header(&format!("functions ({}, {} named)", funcs.len(), named));
    println!(
        "  {:<18} {:>6} {:>5} {:>5}  {}",
        "addr".style(faint()),
        "size".style(faint()),
        "blks".style(faint()),
        "refs".style(faint()),
        "name".style(faint()),
    );
    for f in &funcs {
        let a = f.addr + an.display_base;
        let name_style = if f.named { mint() } else { muted() };
        println!(
            "  {:<18} {:>6} {:>5} {:>5}  {}",
            format!("0x{a:x}").style(faint()),
            f.size,
            f.blocks.len(),
            f.incoming,
            f.name.style(name_style),
        );
    }
    if an.truncated {
        println!(
            "  {}",
            "analysis budget reached — listing is partial".style(amber())
        );
    }
    Ok(())
}

fn dis_function(bin: &crate::model::Binary, bytes: &[u8], sel: &str) -> Result<()> {
    let an = engine::analyze(bin, bytes, 500_000);

    // Resolve the selector: a name, or an address (with or without image base).
    let func = if let Some(f) = an.find_by_name(sel) {
        Some(f)
    } else if let Ok(v) = parse_num(sel) {
        let internal = v.checked_sub(an.display_base).unwrap_or(v);
        an.find_function(internal).or_else(|| an.find_function(v))
    } else {
        None
    };
    let func = func.with_context(|| format!("no function '{sel}' (try `knife funcs`)"))?;

    let a = func.addr + an.display_base;
    section_header(&format!("{} @ 0x{a:x}", func.name));
    println!(
        "  {}",
        format!(
            "{} block(s) · {} bytes · {} incoming ref(s)",
            func.blocks.len(),
            func.size,
            func.incoming
        )
        .style(faint())
    );

    // xrefs into this function
    if let Some(refs) = an.xrefs_to.get(&func.addr) {
        let list: Vec<String> = refs
            .iter()
            .take(8)
            .map(|x| format!("0x{:x}", x.from + an.display_base))
            .collect();
        let more = if refs.len() > 8 {
            format!(" +{}", refs.len() - 8)
        } else {
            String::new()
        };
        println!(
            "  {}",
            format!("xrefs: {}{}", list.join(", "), more).style(faint())
        );
    }
    println!();

    for (i, block) in func.blocks.iter().enumerate() {
        if i > 0 {
            // label incoming block if referenced
            let la = block.start + an.display_base;
            println!("  {}:", format!("loc_{la:x}").style(amber()));
        }
        for ins in &block.insns {
            let a = ins.addr + an.display_base;
            let (mn, rest) = ins.text.split_once(' ').unwrap_or((ins.text.as_str(), ""));

            // annotate branch/call targets
            let annot = if let Some(name) = &ins.target_name {
                format!("  ; {}", name).style(mint()).to_string()
            } else if let Some(t) = ins.target {
                let ta = t + an.display_base;
                let lbl = if an.find_function(t).is_some() {
                    an.label(t)
                } else {
                    format!("loc_{ta:x}")
                };
                format!("  ; {}", lbl).style(faint()).to_string()
            } else {
                String::new()
            };

            println!(
                "  {}  {} {}{}",
                format!("{a:012x}").style(faint()),
                mn.style(accent()),
                rest.style(muted()),
                annot,
            );
        }
    }
    Ok(())
}

fn cmd_hex(file: &str, off: u64, len: usize) -> Result<()> {
    let bytes = load(file)?;
    let start = off as usize;
    if start >= bytes.len() {
        anyhow::bail!("offset 0x{off:x} past end of file ({})", bytes.len());
    }
    let end = (start + len).min(bytes.len());
    section_header(&format!("hex 0x{:x}..0x{:x}", start, end));
    for (row, chunk) in bytes[start..end].chunks(16).enumerate() {
        let addr = start + row * 16;
        let hex: String = chunk
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let sep = if i == 7 { "  " } else { " " };
                format!("{:02x}{}", b, if i == 15 { "" } else { sep })
            })
            .collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!(
            "  {}  {:<48} {}",
            format!("{:08x}", addr).style(faint()),
            hex,
            ascii.style(muted())
        );
    }
    Ok(())
}

fn cmd_map(file: &str, buckets: usize, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let map = analysis::entropy::entropy_map(&bytes, buckets);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&map)?);
        return Ok(());
    }
    section_header("entropy map");
    let step = (bytes.len() / buckets.max(1)).max(1);
    let blocks = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    // one row of sparkline
    let spark: String = map
        .iter()
        .map(|&e| {
            let idx = ((e / 8.0) * 8.0).round() as usize;
            blocks[idx.min(8)]
        })
        .collect();
    println!("  {}", spark.style(accent()));
    println!(
        "  {}",
        format!(
            "{} buckets · {} bytes each · █ = high entropy (packed/encrypted)",
            map.len(),
            step
        )
        .style(faint())
    );
    // flag the hot buckets
    for (i, &e) in map.iter().enumerate() {
        if e >= 7.2 {
            println!(
                "  {} bucket {:>4} @ 0x{:08x}  {:.2}/8",
                marker("bad").style(red()),
                i,
                i * step,
                e
            );
        }
    }
    Ok(())
}

fn cmd_scan(file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    let hits = signatures::scan(&bin, &bytes);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&hits)?);
        return Ok(());
    }
    section_header(&format!("artifacts ({})", hits.len()));
    if hits.is_empty() {
        println!(
            "  {}",
            "no known crypto/packer/embedded signatures".style(faint())
        );
        return Ok(());
    }
    for h in &hits {
        let st = match h.category.as_str() {
            "crypto" | "hash" => amber(),
            "packer" | "embedded" => red(),
            _ => muted(),
        };
        let loc = h.section.as_deref().unwrap_or("-");
        println!(
            "  {}  {:<24} {}",
            format!("0x{:08x}", h.offset).style(faint()),
            h.name.style(st),
            format!("[{}] {} · {}", h.category, loc, h.note).style(faint()),
        );
    }
    Ok(())
}

fn print_yara_match(m: &yara::RuleMatch) {
    let tags = if m.tags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", m.tags.join(", "))
    };
    println!(
        "  {} {}{}",
        marker("bad").style(red()),
        m.rule.style(red()).bold(),
        tags.style(faint())
    );
    if m.namespace != "default" {
        println!(
            "      {}",
            format!("namespace: {}", m.namespace).style(faint())
        );
    }
    for (k, v) in &m.meta {
        println!("      {}", format!("{k}: {v}").style(faint()));
    }
    if !m.patterns.is_empty() {
        let p: Vec<String> = m
            .patterns
            .iter()
            .map(|(id, n)| {
                if *n > 1 {
                    format!("{id}×{n}")
                } else {
                    id.clone()
                }
            })
            .collect();
        println!(
            "      {}",
            format!("strings: {}", p.join(", ")).style(muted())
        );
    }
}

fn cmd_yara(rules: &str, file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let (compiled, rule_count) = yara::compile(rules)?;
    let matches = yara::scan(&compiled, &bytes)?;

    if as_json {
        println!("{}", serde_json::to_string_pretty(&matches)?);
        return Ok(());
    }

    section_header(&format!("yara — {} matched", matches.len()));
    if matches.is_empty() {
        println!(
            "  {}",
            format!("no matches ({rule_count} rule source(s) compiled)").style(faint())
        );
        return Ok(());
    }
    for m in &matches {
        print_yara_match(m);
    }
    Ok(())
}

fn cmd_ls(file: &str) -> Result<()> {
    let bytes = load(file)?;
    let members = formats::list_archive(&bytes)?;
    section_header(&format!("archive members ({})", members.len()));
    for (name, size) in members {
        println!("  {:>10}  {}", human(size).style(faint()), name);
    }
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────

fn parse_num(s: &str) -> Result<u64> {
    let s = s.trim();
    let v = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)?
    } else {
        s.parse::<u64>()?
    };
    Ok(v)
}

fn basename(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max - 1).collect();
        format!("{t}…")
    }
}
