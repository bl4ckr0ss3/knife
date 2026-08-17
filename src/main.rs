//! knife: a reverse engineer's binary Swiss-army knife.
//!
//! Parse, triage, and disassemble PE / ELF / Mach-O. One binary, no runtime.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use owo_colors::{OwoColorize, Style};
use reknife::analysis::{
    capabilities, disasm, driver, engine, hardening, hashes, signatures, sinks, strings as strs,
    triage, yara,
};
use reknife::model::Binary;
use reknife::output::*;
use reknife::{
    analysis, db, formats, listing, mcp, model, tui, workspace::Session, ANALYSIS_BUDGET,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

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

    /// Use this annotation database instead of the one keyed by file hash.
    #[arg(long, global = true, value_name = "PATH")]
    db: Option<String>,

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
    /// Audit exploit mitigations (ASLR, NX, canaries, RELRO, CFG, ...).
    Sec { file: String },
    /// Dangerous-API call sites: the attack surface, with where each is called.
    Sinks {
        file: String,
        /// Only this class (memory, format, exec, alloc, stack, path, random,
        /// privilege).
        #[arg(long)]
        class: Option<String>,
        /// Show every call site instead of the first few per API.
        #[arg(long)]
        all: bool,
    },
    /// Find likely bugs: sink call sites whose arguments look exploitable.
    Audit {
        file: String,
        /// Only show findings reachable from an entry point or export.
        #[arg(long)]
        reachable: bool,
    },
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
    /// Kernel-driver / BYOVD analysis: identity, devices & symlinks, IRP
    /// dispatch, IOCTL surface, and kernel primitives with call sites.
    Drv {
        file: String,
        /// Only show primitives reachable from the entry point or an IRP
        /// dispatch handler (i.e. user mode can plausibly drive them).
        #[arg(long)]
        reachable: bool,
    },
    /// Disassemble (x86/x64, AArch64) from the entry point, a location, or a function.
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
    /// Pseudocode view of a function (x86/x64): lifted, with calls and their
    /// arguments. Not a full decompiler; unmodelled instructions show as asm.
    Pseudo {
        file: String,
        /// Function to lift, by name or address.
        func: String,
    },
    /// Find what references a function, import, address, or string.
    Xrefs {
        file: String,
        /// Function name, imported API, or address to look up.
        target: Option<String>,
        /// Instead of a symbol, find references to strings containing this text.
        #[arg(long)]
        str: Option<String>,
    },
    /// Show how a sink is reached: call chains from entry points and exports.
    Paths {
        file: String,
        /// Function, imported API, or address to reach.
        target: String,
        /// Start only from this function instead of every entry point/export.
        #[arg(long)]
        from: Option<String>,
        /// Maximum number of chains to print.
        #[arg(long, default_value_t = 10)]
        max: usize,
    },
    /// Export a function CFG or the recovered whole-program call graph.
    Graph {
        file: String,
        /// Export this function's control-flow graph instead of the call graph.
        #[arg(long)]
        func: Option<String>,
        /// Root the call graph at this function. Repeat for multiple roots.
        #[arg(long = "from", value_name = "FUNC")]
        from: Vec<String>,
        /// Root the call graph at the program entry point and exports.
        #[arg(long)]
        reachable: bool,
        /// Emit Graphviz DOT instead of the terminal report.
        #[arg(long)]
        dot: bool,
    },
    /// Name an address, so every later command calls it that.
    Name {
        file: String,
        /// Address to name.
        addr: String,
        /// The name. Omit with --clear to remove it.
        name: Option<String>,
        /// Forget the name and note stored at this address.
        #[arg(long)]
        clear: bool,
    },
    /// Leave a note at an address; it shows up in the disassembly.
    Note {
        file: String,
        addr: String,
        text: Option<String>,
        /// Forget the name and note stored at this address.
        #[arg(long)]
        clear: bool,
    },
    /// Define or rename a field in a reusable user type.
    Field {
        file: String,
        /// User type whose layout owns the field.
        #[arg(long = "type", value_name = "TYPE")]
        type_name: String,
        /// Signed byte offset (`0x18` or `-0x8`).
        offset: String,
        /// C-style field name. Omit with --clear.
        name: Option<String>,
        /// Optional C data type for this member (`u32`, `IRP *`, ...).
        #[arg(long = "data-type", value_name = "TYPE")]
        data_type: Option<String>,
        /// Remove this field definition.
        #[arg(long)]
        clear: bool,
    },
    /// Bind a pseudocode pointer base to a reusable user type.
    Type {
        file: String,
        /// Function containing the base, by name or address.
        #[arg(long)]
        func: String,
        /// Stable pseudocode base (`rcx`, `rdi`, `var_8`, ...).
        base: String,
        /// User type to bind. Omit with --clear.
        type_name: Option<String>,
        /// Remove this function/base binding.
        #[arg(long)]
        clear: bool,
    },
    /// Rename a recovered pseudocode register, argument, or local in one function.
    Var {
        file: String,
        /// Function containing the recovered variable, by name or address.
        #[arg(long)]
        func: String,
        /// Stable recovered identity (`rcx`, `arg_8`, `var_20`, ...).
        base: String,
        /// Source-style display name. Omit with --clear.
        name: Option<String>,
        /// Remove the stored alias and show the recovered identity again.
        #[arg(long)]
        clear: bool,
    },
    /// Stage, inspect, clear, or export binary byte patches safely.
    Patch {
        file: String,
        /// Patch location as a virtual address (PE accepts VA or RVA).
        #[arg(long, value_name = "ADDR")]
        vaddr: Option<String>,
        /// Patch location as a raw file offset.
        #[arg(long, value_name = "OFFSET")]
        off: Option<String>,
        /// Replacement bytes (`90 90`, `9090`, `0x90,0x90`, or `\\x90\\x90`).
        #[arg(long, value_name = "HEX")]
        bytes: Option<String>,
        /// Clear the staged run at the location, or `--len` bytes from it.
        #[arg(long)]
        clear: bool,
        /// Number of staged bytes to clear from the selected location.
        #[arg(long)]
        len: Option<usize>,
        /// Atomically write all staged patches to a new binary.
        #[arg(long, value_name = "PATH")]
        export: Option<String>,
        /// Replace an existing export path. The input binary is never allowed.
        #[arg(long)]
        force: bool,
    },
    /// Set an exact persistent function prototype for pseudocode and calls.
    Proto {
        file: String,
        /// Function to describe, by name or address.
        #[arg(long)]
        func: String,
        /// Exact C return type (`void`, `bool`, `CONTEXT *`, ...).
        #[arg(long)]
        returns: Option<String>,
        /// Ordered C parameter type. Repeat once per ABI parameter.
        #[arg(long = "param", value_name = "TYPE")]
        params: Vec<String>,
        /// Remove the stored prototype.
        #[arg(long)]
        clear: bool,
    },
    /// Export or import portable cross-binary structure layouts.
    #[command(name = "typelib")]
    TypeLib {
        file: String,
        /// Write this binary database's reusable layouts to a JSON library.
        #[arg(long, value_name = "PATH")]
        export: Option<String>,
        /// Merge a JSON type library into this binary database.
        #[arg(long, value_name = "PATH")]
        import: Option<String>,
        /// Replace each imported type as a unit instead of rejecting conflicts.
        #[arg(long)]
        replace: bool,
    },
    /// Show everything stored for a binary.
    Db { file: String },
    /// Open the interactive view: functions, listing, xrefs, naming and notes.
    Tui { file: String },
    /// Run a Model Context Protocol server over stdio (tools for agents).
    Mcp,
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
    /// Emit a shell completion script (bash, zsh, fish, powershell, elvish).
    Completions { shell: clap_complete::Shell },
    /// Compare two binaries: functions, imports, and sections. Exit code 1
    /// when anything changed.
    Diff { a: String, b: String },
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
        "sec",
        "sinks",
        "audit",
        "strings",
        "iocs",
        "hashes",
        "drv",
        "dis",
        "pseudo",
        "xrefs",
        "paths",
        "graph",
        "name",
        "note",
        "field",
        "type",
        "var",
        "patch",
        "proto",
        "typelib",
        "db",
        "tui",
        "mcp",
        "hex",
        "map",
        "scan",
        "yara",
        "funcs",
        "ls",
        "completions",
        "diff",
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
        Command::Sec { file } => cmd_sec(&file, cli.json),
        Command::Sinks { file, class, all } => {
            cmd_sinks(&file, class.as_deref(), all, cli.json, cli.db.as_deref())
        }
        Command::Audit { file, reachable } => {
            cmd_audit(&file, reachable, cli.json, cli.db.as_deref())
        }
        Command::Strings { file, min } => cmd_strings(&file, min, cli.json),
        Command::Iocs { file } => cmd_iocs(&file, cli.json),
        Command::Hashes { file } => cmd_hashes(&file, cli.json),
        Command::Drv { file, reachable } => cmd_drv(&file, reachable, cli.json, cli.db.as_deref()),
        Command::Dis {
            file,
            count,
            vaddr,
            off,
            func,
        } => cmd_dis(&file, count, vaddr, off, func, cli.db.as_deref()),
        Command::Pseudo { file, func } => cmd_pseudo(&file, &func, cli.db.as_deref()),
        Command::Xrefs { file, target, str } => cmd_xrefs(
            &file,
            target.as_deref(),
            str.as_deref(),
            cli.json,
            cli.db.as_deref(),
        ),
        Command::Paths {
            file,
            target,
            from,
            max,
        } => cmd_paths(
            &file,
            &target,
            from.as_deref(),
            max,
            cli.json,
            cli.db.as_deref(),
        ),
        Command::Graph {
            file,
            func,
            from,
            reachable,
            dot,
        } => cmd_graph(
            &file,
            func.as_deref(),
            &from,
            reachable,
            dot,
            cli.json,
            cli.db.as_deref(),
        ),
        Command::Name {
            file,
            addr,
            name,
            clear,
        } => cmd_annotate(
            &file,
            &addr,
            name.as_deref(),
            None,
            clear,
            cli.db.as_deref(),
        ),
        Command::Note {
            file,
            addr,
            text,
            clear,
        } => cmd_annotate(
            &file,
            &addr,
            None,
            text.as_deref(),
            clear,
            cli.db.as_deref(),
        ),
        Command::Field {
            file,
            type_name,
            offset,
            name,
            data_type,
            clear,
        } => cmd_field(
            &file,
            &type_name,
            &offset,
            name.as_deref(),
            data_type.as_deref(),
            clear,
            cli.db.as_deref(),
        ),
        Command::Type {
            file,
            func,
            base,
            type_name,
            clear,
        } => cmd_type_binding(
            &file,
            &func,
            &base,
            type_name.as_deref(),
            clear,
            cli.db.as_deref(),
        ),
        Command::Var {
            file,
            func,
            base,
            name,
            clear,
        } => cmd_variable(
            &file,
            &func,
            &base,
            name.as_deref(),
            clear,
            cli.db.as_deref(),
        ),
        Command::Patch {
            file,
            vaddr,
            off,
            bytes,
            clear,
            len,
            export,
            force,
        } => cmd_patch(
            &file,
            PatchArgs {
                vaddr: vaddr.as_deref(),
                off: off.as_deref(),
                bytes: bytes.as_deref(),
                clear,
                len,
                export: export.as_deref(),
                force,
            },
            cli.json,
            cli.db.as_deref(),
        ),
        Command::Proto {
            file,
            func,
            returns,
            params,
            clear,
        } => cmd_prototype(
            &file,
            &func,
            returns.as_deref(),
            &params,
            clear,
            cli.db.as_deref(),
        ),
        Command::TypeLib {
            file,
            export,
            import,
            replace,
        } => cmd_type_library(
            &file,
            export.as_deref(),
            import.as_deref(),
            replace,
            cli.db.as_deref(),
        ),
        Command::Db { file } => cmd_db(&file, cli.db.as_deref(), cli.json),
        Command::Tui { file } => cmd_tui(&file, cli.db.as_deref()),
        Command::Mcp => mcp::run(),
        Command::Funcs { file, by_refs } => cmd_funcs(&file, by_refs, cli.json, cli.db.as_deref()),
        Command::Hex { file, off, len } => cmd_hex(&file, off, len),
        Command::Map { file, buckets } => cmd_map(&file, buckets, cli.json),
        Command::Scan { file } => cmd_scan(&file, cli.json),
        Command::Yara { rules, file } => cmd_yara(&rules, &file, cli.json),
        Command::Ls { file } => cmd_ls(&file),
        Command::Completions { shell } => {
            use clap::CommandFactory;
            use std::io::Write;
            let mut stdout = std::io::stdout();
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "knife", &mut stdout);
            stdout.flush().context("cannot flush stdout")?;
            Ok(())
        }
        Command::Diff { a, b } => {
            let changed = cmd_diff(&a, &b)?;
            // A diff is the kind of command scripts inspect with the exit
            // status: 0 = no change, 1 = something changed.
            if changed {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

/// The analysis instruction budget, shared by every command that recovers the
/// CFG. Keeping it uniform is what guarantees that a site `audit` reports can
/// always be shown by `dis --func`: a smaller budget here would let one command
/// find code another cannot display.
fn load(file: &str) -> Result<Vec<u8>> {
    std::fs::read(file).with_context(|| format!("cannot read {file}"))
}

fn parse(file: &str, bytes: &[u8]) -> Result<Binary> {
    formats::analyze(file, bytes)
}

/// Open the annotation database for a target. Identity is the file's content,
/// so the work follows the bytes rather than the path they arrived at.
fn open_db(file: &str, bytes: &[u8], explicit: Option<&str>) -> Result<db::Db> {
    db::Db::load(&hashes::sha256_hex(bytes), file, explicit)
}

/// Addresses are shown and typed as virtual addresses but stored relative to
/// the image base, so a database stays valid if the image is ever rebased.
fn to_stored(bin: &Binary, va: u64) -> u64 {
    va.wrapping_sub(engine::display_base(bin))
}

fn cmd_annotate(
    file: &str,
    addr: &str,
    name: Option<&str>,
    note: Option<&str>,
    clear: bool,
    db_path: Option<&str>,
) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    let va = parse_num(addr).with_context(|| format!("'{addr}' is not an address"))?;
    let at = to_stored(&bin, va);
    let mut store = open_db(file, &bytes, db_path)?;

    if clear {
        let (n, c) = store.clear(at);
        if n.is_none() && c.is_none() {
            anyhow::bail!("nothing stored at 0x{va:x}");
        }
        store.save()?;
        println!("  {} 0x{va:x}", "cleared".style(faint()));
        return Ok(());
    }

    match (name, note) {
        (Some(n), _) => {
            store.set_name(at, n);
            println!("  {} 0x{va:x}  {}", "named".style(faint()), n.style(mint()));
        }
        (_, Some(t)) => {
            store.set_note(at, t);
            println!(
                "  {} 0x{va:x}  {}",
                "noted".style(faint()),
                t.style(muted())
            );
        }
        (None, None) => anyhow::bail!("give a value, or --clear to remove what is there"),
    }
    store.save()?;
    Ok(())
}

fn cmd_field(
    file: &str,
    type_name: &str,
    offset: &str,
    name: Option<&str>,
    data_type: Option<&str>,
    clear: bool,
    db_path: Option<&str>,
) -> Result<()> {
    let bytes = load(file)?;
    let mut store = open_db(file, &bytes, db_path)?;
    let offset = parse_signed_num(offset)
        .with_context(|| format!("'{offset}' is not a signed byte offset"))?;
    if clear {
        if data_type.is_some() {
            anyhow::bail!("--data-type cannot be used with --clear")
        }
        let Some(old) = store.clear_field(type_name, offset) else {
            anyhow::bail!("no field stored for {type_name} at {offset:+#x}")
        };
        store.save()?;
        println!(
            "  {} {}{:+#x}  {}",
            "cleared".style(faint()),
            type_name.style(mint()),
            offset,
            old.style(muted())
        );
        return Ok(());
    }
    let name = name.context("give a field name, or use --clear")?;
    store.set_typed_field(type_name, offset, name, data_type)?;
    store.save()?;
    println!(
        "  {} {}{:+#x}  {}",
        "field".style(faint()),
        type_name.style(mint()),
        offset,
        match data_type {
            Some(ty) => format!("{name}: {ty}"),
            None => name.to_string(),
        }
        .style(mint())
    );
    Ok(())
}

fn cmd_type_binding(
    file: &str,
    selector: &str,
    requested_base: &str,
    type_name: Option<&str>,
    clear: bool,
    db_path: Option<&str>,
) -> Result<()> {
    let mut sess = Session::open(file, db_path, ANALYSIS_BUDGET, "type binding")?;
    let function = if let Some(f) = sess.an.find_by_name(selector) {
        Some(f)
    } else if let Ok(value) = parse_num(selector) {
        let internal = value.checked_sub(sess.an.display_base).unwrap_or(value);
        sess.an
            .find_function(internal)
            .or_else(|| sess.an.find_function(value))
    } else {
        None
    }
    .with_context(|| format!("no function '{selector}' (try `knife funcs`)"))?;
    let stored = function.addr.wrapping_sub(sess.an.display_base);
    let function_name = function.name.clone();
    let base = sess
        .db
        .variables
        .iter()
        .find_map(|((owner, recovered), alias)| {
            (*owner == stored && alias == requested_base).then_some(recovered.clone())
        })
        .unwrap_or_else(|| requested_base.to_string());
    let strings = listing::string_map(&sess.bin, &sess.bytes, engine::display_base(&sess.bin));
    let base_exists = sess.db.variables.contains_key(&(stored, base.clone()))
        || analysis::ir::decompile(&sess.an, &sess.bin, function, &strings, &sess.db)
            .iter()
            .any(|line| contains_identifier(&line.text, requested_base));
    if !base_exists {
        anyhow::bail!("base '{requested_base}' does not appear in {function_name}'s pseudocode")
    }
    if clear {
        let Some(old) = sess.db.clear_binding(stored, &base) else {
            anyhow::bail!("no type bound to {function_name}:{requested_base}")
        };
        sess.db.save()?;
        println!(
            "  {} {}:{}  {}",
            "cleared".style(faint()),
            function_name.style(mint()),
            base.style(muted()),
            old.style(muted())
        );
        return Ok(());
    }
    let type_name = type_name.context("give a type name, or use --clear")?;
    sess.db.bind_type(stored, &base, type_name)?;
    sess.db.save()?;
    println!(
        "  {} {}:{}  {}",
        "bound".style(faint()),
        function_name.style(mint()),
        base.style(muted()),
        type_name.style(mint())
    );
    Ok(())
}

fn cmd_variable(
    file: &str,
    selector: &str,
    requested_base: &str,
    name: Option<&str>,
    clear: bool,
    db_path: Option<&str>,
) -> Result<()> {
    let mut sess = Session::open(file, db_path, ANALYSIS_BUDGET, "variable renaming")?;
    let function = if let Some(function) = sess.an.find_by_name(selector) {
        Some(function)
    } else if let Ok(value) = parse_num(selector) {
        let internal = value.checked_sub(sess.an.display_base).unwrap_or(value);
        sess.an
            .find_function(internal)
            .or_else(|| sess.an.find_function(value))
    } else {
        None
    }
    .with_context(|| format!("no function '{selector}' (try `knife funcs`)"))?;
    let stored = function.addr.wrapping_sub(sess.an.display_base);
    let function_name = function.name.clone();
    let recovered = sess
        .db
        .variables
        .iter()
        .find_map(|((owner, base), alias)| {
            (*owner == stored && alias == requested_base).then_some(base.clone())
        })
        .unwrap_or_else(|| requested_base.to_string());
    let strings = listing::string_map(&sess.bin, &sess.bytes, engine::display_base(&sess.bin));
    let appears = sess.db.variables.contains_key(&(stored, recovered.clone()))
        || analysis::ir::decompile(&sess.an, &sess.bin, function, &strings, &sess.db)
            .iter()
            .any(|line| contains_identifier(&line.text, requested_base));
    if !appears {
        anyhow::bail!("variable '{requested_base}' does not appear in {function_name}'s pseudocode")
    }
    if clear {
        let Some(old) = sess.db.clear_variable(stored, &recovered) else {
            anyhow::bail!("no alias stored for {function_name}:{requested_base}")
        };
        sess.db.save()?;
        println!(
            "  {} {}:{}  {}",
            "cleared".style(faint()),
            function_name.style(mint()),
            recovered.style(muted()),
            old.style(muted())
        );
        return Ok(());
    }
    let name = name.context("give a variable name, or use --clear")?;
    sess.db.set_variable(stored, &recovered, name)?;
    sess.db.save()?;
    println!(
        "  {} {}:{}  {}",
        "variable".style(faint()),
        function_name.style(mint()),
        recovered.style(muted()),
        name.style(mint())
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct PatchArgs<'a> {
    vaddr: Option<&'a str>,
    off: Option<&'a str>,
    bytes: Option<&'a str>,
    clear: bool,
    len: Option<usize>,
    export: Option<&'a str>,
    force: bool,
}

fn cmd_patch(file: &str, args: PatchArgs<'_>, as_json: bool, db_path: Option<&str>) -> Result<()> {
    let original = load(file)?;
    let bin = parse(file, &original)?;
    let mut store = open_db(file, &original, db_path)?;

    if let Some(output) = args.export {
        if args.vaddr.is_some()
            || args.off.is_some()
            || args.bytes.is_some()
            || args.clear
            || args.len.is_some()
        {
            anyhow::bail!("--export cannot be combined with a patch location or edit")
        }
        if store.patches.is_empty() {
            anyhow::bail!("no staged patches to export")
        }
        let output_path = std::path::Path::new(output);
        let input_path = std::fs::canonicalize(file)
            .with_context(|| format!("cannot resolve input path {file}"))?;
        if output_path.exists()
            && std::fs::canonicalize(output_path).is_ok_and(|candidate| candidate == input_path)
        {
            anyhow::bail!("refusing to overwrite the input binary")
        }
        if output_path.exists() && !args.force {
            anyhow::bail!("{} already exists (use --force)", output_path.display())
        }
        let patched = store.apply_patches(&original)?;
        if let Some(parent) = output_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let tmp = output_path.with_extension(format!("knife-patch.{}.tmp", std::process::id()));
        std::fs::write(&tmp, &patched)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        if output_path.exists() {
            std::fs::remove_file(output_path)
                .with_context(|| format!("cannot replace {}", output_path.display()))?;
        }
        if let Err(error) = std::fs::rename(&tmp, output_path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(error).with_context(|| format!("cannot write {}", output_path.display()));
        }
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "output": output_path.display().to_string(),
                    "bytes": patched.len(),
                    "patched_bytes": store.patches.len(),
                    "sha256": hashes::sha256_hex(&patched),
                    "signature_invalidated": bin.has_signature,
                }))?
            );
        } else {
            println!(
                "  {} {}  {} patched byte{}  sha256 {}",
                "exported".style(faint()),
                output_path.display().style(mint()),
                store.patches.len(),
                plural(store.patches.len()),
                hashes::sha256_hex(&patched).style(muted())
            );
            if bin.has_signature {
                println!(
                    "  {}",
                    "warning: changing bytes invalidates the binary's existing digital signature"
                        .style(amber())
                );
            }
        }
        return Ok(());
    }

    if args.force {
        anyhow::bail!("--force is valid only with --export")
    }
    if args.vaddr.is_none() && args.off.is_none() {
        if args.bytes.is_some() || args.clear || args.len.is_some() {
            anyhow::bail!("give exactly one of --vaddr or --off for this edit")
        }
        return print_patch_workspace(&bin, &store, as_json);
    }
    let offset = patch_offset(&bin, args.vaddr, args.off)?;
    if args.clear {
        if args.bytes.is_some() {
            anyhow::bail!("--clear cannot be combined with --bytes")
        }
        let restored = match args.len {
            Some(0) => anyhow::bail!("--len must be greater than zero"),
            Some(len) => store.clear_patch_range(offset, len),
            None => store.clear_patch_run_at(offset),
        };
        if restored.is_empty() {
            anyhow::bail!("no staged patch at file offset {offset:#x}")
        }
        store.save()?;
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "action": "cleared",
                    "offset": offset,
                    "bytes": restored.len(),
                }))?
            );
        } else {
            println!(
                "  {} {:#x}  {} byte{} restored",
                "cleared".style(faint()),
                offset,
                restored.len(),
                plural(restored.len())
            );
        }
        return Ok(());
    }
    if args.len.is_some() {
        anyhow::bail!("--len is valid only with --clear")
    }
    let bytes = db::parse_patch_bytes(args.bytes.context("give --bytes HEX, or use --clear")?)?;
    store.stage_patch(&original, offset, &bytes)?;
    store.save()?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "action": "staged",
                "offset": offset,
                "bytes": bytes,
                "staged_bytes": store.patches.len(),
            }))?
        );
    } else {
        println!(
            "  {} {:#x}  {}  ({} total staged byte{})",
            "patched".style(faint()),
            offset,
            format_patch_bytes(&bytes).style(mint()),
            store.patches.len(),
            plural(store.patches.len())
        );
    }
    Ok(())
}

fn patch_offset(bin: &Binary, vaddr: Option<&str>, off: Option<&str>) -> Result<u64> {
    match (vaddr, off) {
        (Some(_), Some(_)) | (None, None) => {
            anyhow::bail!("give exactly one of --vaddr or --off")
        }
        (None, Some(offset)) => {
            parse_num(offset).with_context(|| format!("'{offset}' is not a file offset"))
        }
        (Some(address), None) => {
            let requested =
                parse_num(address).with_context(|| format!("'{address}' is not an address"))?;
            let base = engine::display_base(bin);
            let va = if base != 0 && requested < base {
                requested
                    .checked_add(base)
                    .context("virtual address overflows")?
            } else {
                requested
            };
            engine::va_to_off(bin, base, va)
                .map(|offset| offset as u64)
                .with_context(|| format!("virtual address 0x{va:x} is not mapped in the file"))
        }
    }
}

fn print_patch_workspace(bin: &Binary, store: &db::Db, as_json: bool) -> Result<()> {
    let base = engine::display_base(bin);
    let runs = store.patch_runs();
    if as_json {
        let rows: Vec<_> = runs
            .iter()
            .map(|run| {
                json!({
                    "offset": run.offset,
                    "vaddr": engine::off_to_va(bin, base, run.offset),
                    "original": format_patch_bytes(&run.original),
                    "bytes": format_patch_bytes(&run.bytes),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    section_header(&format!(
        "patch workspace ({} run{}, {} byte{})",
        runs.len(),
        plural(runs.len()),
        store.patches.len(),
        plural(store.patches.len())
    ));
    if runs.is_empty() {
        println!("  {}", "no staged patches".style(faint()));
        return Ok(());
    }
    for run in runs {
        let va = engine::off_to_va(bin, base, run.offset)
            .map(|address| format!("0x{address:x}"))
            .unwrap_or_else(|| "unmapped".into());
        println!(
            "  off {:#010x}  va {:<18}  {} {} {}",
            run.offset,
            va.style(faint()),
            format_patch_bytes(&run.original).style(muted()),
            "→".style(accent()),
            format_patch_bytes(&run.bytes).style(mint())
        );
    }
    Ok(())
}

fn format_patch_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn cmd_prototype(
    file: &str,
    selector: &str,
    returns: Option<&str>,
    params: &[String],
    clear: bool,
    db_path: Option<&str>,
) -> Result<()> {
    let mut sess = Session::open(file, db_path, ANALYSIS_BUDGET, "prototype editing")?;
    let function = if let Some(function) = sess.an.find_by_name(selector) {
        Some(function)
    } else if let Ok(value) = parse_num(selector) {
        let internal = value.checked_sub(sess.an.display_base).unwrap_or(value);
        sess.an
            .find_function(internal)
            .or_else(|| sess.an.find_function(value))
    } else {
        None
    }
    .with_context(|| format!("no function '{selector}' (try `knife funcs`)"))?;
    let stored = function.addr.wrapping_sub(sess.an.display_base);
    let function_name = function.name.clone();

    if clear {
        if returns.is_some() || !params.is_empty() {
            anyhow::bail!("--clear cannot be combined with --returns or --param")
        }
        let Some(old) = sess.db.clear_prototype(stored) else {
            anyhow::bail!("no prototype stored for {function_name}")
        };
        sess.db.save()?;
        println!(
            "  {} {}  {} ({})",
            "cleared".style(faint()),
            function_name.style(mint()),
            old.returns.style(muted()),
            old.params.join(", ").style(muted())
        );
        return Ok(());
    }

    let returns = returns.context("give --returns TYPE, or use --clear")?;
    sess.db.set_prototype(stored, returns, params)?;
    sess.db.save()?;
    println!(
        "  {} {}  {} ({})",
        "prototype".style(faint()),
        function_name.style(mint()),
        returns.style(mint()),
        params.join(", ").style(muted())
    );
    Ok(())
}

fn cmd_type_library(
    file: &str,
    export: Option<&str>,
    import: Option<&str>,
    replace: bool,
    db_path: Option<&str>,
) -> Result<()> {
    match (export, import) {
        (Some(_), Some(_)) => anyhow::bail!("choose exactly one of --export or --import"),
        (None, None) => anyhow::bail!("give --export PATH or --import PATH"),
        (Some(_), None) if replace => anyhow::bail!("--replace is valid only with --import"),
        _ => {}
    }
    let bytes = load(file)?;
    let mut store = open_db(file, &bytes, db_path)?;
    if let Some(path) = export {
        let summary = store.export_type_library(std::path::Path::new(path))?;
        println!(
            "  {} {} type{} · {} field{}  {}",
            "exported".style(faint()),
            summary.types,
            plural(summary.types),
            summary.fields,
            plural(summary.fields),
            path.style(mint())
        );
        return Ok(());
    }

    let path = import.expect("validated above");
    let summary = store.import_type_library(std::path::Path::new(path), replace)?;
    store.save()?;
    println!(
        "  {} {} type{} · {} field{}{}  {}",
        "imported".style(faint()),
        summary.types,
        plural(summary.types),
        summary.fields,
        plural(summary.fields),
        if replace {
            " · replaced conflicts"
        } else {
            ""
        },
        path.style(mint())
    );
    Ok(())
}

fn cmd_tui(file: &str, db_path: Option<&str>) -> Result<()> {
    let original = load(file)?;
    let original_bin = parse(file, &original)?;
    let db = open_db(file, &original, db_path)?;
    let bytes = db.apply_patches(&original)?;
    let bin = if db.patches.is_empty() {
        original_bin
    } else {
        parse(file, &bytes).context("staged patches make the binary unparsable")?
    };
    if !disasm::supported(bin.arch) {
        anyhow::bail!(
            "the interactive view needs x86/x64 disassembly; this is {}",
            bin.arch.label()
        );
    }
    let title = basename(file).to_string();
    // The analysis itself runs inside `tui::run`, on a worker thread, so the
    // animated splash plays while the engine works instead of after it.
    tui::run(bin, bytes, db, title)
}

fn cmd_db(file: &str, db_path: Option<&str>, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    let store = open_db(file, &bytes, db_path)?;
    let base = engine::display_base(&bin);

    if as_json {
        let mut addrs: Vec<u64> = store
            .names
            .keys()
            .chain(store.notes.keys())
            .copied()
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "sha256": store.sha256,
                "path": store.path().map(|p| p.display().to_string()),
                "entries": addrs.iter().map(|a| json!({
                    "addr": a + base,
                    "name": store.names.get(a),
                    "note": store.notes.get(a),
                })).collect::<Vec<_>>(),
                "types": store.fields.iter().map(|(type_name, fields)| json!({
                    "name": type_name,
                    "fields": fields.iter().map(|(offset, field)| json!({
                        "offset": offset,
                        "name": field.name,
                        "data_type": field.data_type,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "bindings": store.bindings.iter().map(|((function, pointer_base), type_name)| json!({
                    "function": function + base,
                    "base": pointer_base,
                    "type": type_name,
                })).collect::<Vec<_>>(),
                "variables": store.variables.iter().map(|((function, recovered), name)| json!({
                    "function": function + base,
                    "base": recovered,
                    "name": name,
                })).collect::<Vec<_>>(),
                "prototypes": store.prototypes.iter().map(|(function, prototype)| json!({
                    "function": function + base,
                    "returns": prototype.returns,
                    "params": prototype.params,
                })).collect::<Vec<_>>(),
                "patches": store.patch_runs().iter().map(|run| json!({
                    "offset": run.offset,
                    "vaddr": engine::off_to_va(&bin, base, run.offset),
                    "original": format_patch_bytes(&run.original),
                    "bytes": format_patch_bytes(&run.bytes),
                })).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    section_header(&format!(
        "database ({} entr{})",
        store.len(),
        if store.len() == 1 { "y" } else { "ies" }
    ));
    if let Some(p) = store.path() {
        kv("file", p.display());
    }
    kv("sha256", &store.sha256);

    if store.is_empty() {
        println!();
        println!(
            "  {}",
            "nothing stored yet; `knife name`, `note`, `field`, `type`, `var`, `proto`, and `patch` write here"
                .style(faint())
        );
        return Ok(());
    }

    let mut addrs: Vec<u64> = store
        .names
        .keys()
        .chain(store.notes.keys())
        .copied()
        .collect();
    addrs.sort_unstable();
    addrs.dedup();

    println!();
    for a in addrs {
        let shown = a + base;
        let name = store.names.get(&a).map(String::as_str).unwrap_or("");
        println!(
            "  {}  {:<28} {}",
            format!("0x{shown:x}").style(faint()),
            name.style(mint()),
            store
                .notes
                .get(&a)
                .map(String::as_str)
                .unwrap_or("")
                .style(muted()),
        );
    }
    if !store.fields.is_empty() {
        println!();
        println!("  {}", "types".style(amber()).bold());
        for (type_name, fields) in &store.fields {
            for (offset, field) in fields {
                println!(
                    "  {:<24} {:+#06x}  {}",
                    type_name.style(mint()),
                    offset,
                    field.style(mint())
                );
            }
        }
    }
    if !store.bindings.is_empty() {
        println!();
        println!("  {}", "type bindings".style(amber()).bold());
        for ((function, pointer_base), type_name) in &store.bindings {
            println!(
                "  0x{:x}:{:<12} {}",
                function + base,
                pointer_base.style(muted()),
                type_name.style(mint())
            );
        }
    }
    if !store.variables.is_empty() {
        println!();
        println!("  {}", "variable aliases".style(amber()).bold());
        for ((function, recovered), name) in &store.variables {
            println!(
                "  0x{:x}:{:<12} {}",
                function + base,
                recovered.style(muted()),
                name.style(mint())
            );
        }
    }
    if !store.prototypes.is_empty() {
        println!();
        println!("  {}", "function prototypes".style(amber()).bold());
        for (function, prototype) in &store.prototypes {
            println!(
                "  0x{:x}  {} ({})",
                function + base,
                prototype.returns.style(mint()),
                prototype.params.join(", ").style(muted())
            );
        }
    }
    if !store.patches.is_empty() {
        println!();
        println!("  {}", "staged patches".style(amber()).bold());
        for run in store.patch_runs() {
            let address = engine::off_to_va(&bin, base, run.offset)
                .map(|value| format!("0x{value:x}"))
                .unwrap_or_else(|| "unmapped".into());
            println!(
                "  off {:#010x}  va {:<18}  {} {} {}",
                run.offset,
                address.style(faint()),
                format_patch_bytes(&run.original).style(muted()),
                "→".style(accent()),
                format_patch_bytes(&run.bytes).style(mint())
            );
        }
    }
    Ok(())
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

    // mitigations, one line; `knife sec` carries the reasoning
    let sec = hardening::run(&bin);
    if !sec.findings.is_empty() {
        section_header("mitigations");
        let cells: Vec<String> = sec
            .findings
            .iter()
            .filter(|f| f.state != hardening::State::NotApplicable)
            .map(|f| {
                let st = match f.state {
                    hardening::State::On => mint(),
                    hardening::State::Partial => amber(),
                    _ => red(),
                };
                format!("{} {}", marker(f.state.kind()).style(st), f.name.style(st))
            })
            .collect();
        println!("  {}", cells.join("   "));
        println!(
            "  {}",
            format!(
                "{} · {} of {} missing or weakened · run `knife sec` for detail",
                sec.exposure.label(),
                sec.missing,
                sec.applicable
            )
            .style(faint())
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
        section_header(&format!("indicators ({}), defanged", iocs.len()));
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
            let insns = disasm::disassemble(&bytes, off, va, bin.bits, bin.arch, 8);
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

fn cmd_sec(file: &str, as_json: bool) -> Result<()> {
    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    let rep = hardening::run(&bin);

    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep)?);
        return Ok(());
    }

    if rep.findings.is_empty() {
        anyhow::bail!(
            "no mitigation model for {} binaries",
            bin.format.label().to_lowercase()
        );
    }

    section_header("mitigations");
    for f in &rep.findings {
        let st = match f.state {
            hardening::State::On => mint(),
            hardening::State::Partial => amber(),
            hardening::State::Off => red(),
            hardening::State::NotApplicable => faint(),
        };
        println!(
            "  {} {:<20} {:<10} {}",
            marker(f.state.kind()).style(st),
            f.name.style(st),
            f.state.label().style(st),
            f.detail.style(muted()),
        );
        // The consequence line is the point of the command, so it is always
        // printed rather than hidden behind a verbose flag.
        println!("  {:<4}{}", "", f.impact.style(faint()));
    }

    let style = match rep.exposure {
        hardening::Exposure::Hardened => mint(),
        hardening::Exposure::Moderate => muted(),
        hardening::Exposure::Weak => amber(),
        hardening::Exposure::Bare => red(),
    };
    println!();
    println!(
        "  {}   {}",
        rep.exposure.label().style(style).bold(),
        format!(
            "exposure score {} · {} of {} mitigations missing or weakened",
            rep.score, rep.missing, rep.applicable
        )
        .style(faint())
    );
    Ok(())
}

fn cmd_sinks(
    file: &str,
    class: Option<&str>,
    all: bool,
    as_json: bool,
    db_path: Option<&str>,
) -> Result<()> {
    let s = Session::open(file, db_path, ANALYSIS_BUDGET, "call-site recovery")?;
    let an = &s.an;
    let mut hits = sinks::find(an);
    if let Some(c) = class {
        hits.retain(|h| h.class.eq_ignore_ascii_case(c));
    }

    if as_json {
        // Addresses are shifted into display space so they match every other
        // command's output and can be pasted straight into a debugger.
        let out: Vec<_> = hits
            .iter()
            .map(|h| {
                json!({
                    "api": h.api, "class": h.class, "note": h.note,
                    "severity": h.severity, "local": h.local,
                    "via": h.via.iter().map(|a| a + an.display_base).collect::<Vec<_>>(),
                    "sites": h.sites.iter().map(|s| json!({
                        "from": s.from + an.display_base,
                        "in": s.in_func, "offset": s.at_off,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let total: usize = hits.iter().map(|h| h.sites.len()).sum();
    section_header(&format!(
        "sinks ({} APIs, {} call sites)",
        hits.len(),
        total
    ));
    if hits.is_empty() {
        println!("  {}", "no catalogued sink is imported".style(faint()));
        return Ok(());
    }

    let cluster = sinks::cluster(&hits);
    let line: Vec<String> = cluster.iter().map(|(k, v)| format!("{k} ×{v}")).collect();
    println!("  {}", line.join("   ").style(amber()));
    println!();

    for h in &hits {
        let st = match h.severity {
            3 => red(),
            2 => amber(),
            _ => muted(),
        };
        let kind = match h.severity {
            3 => "bad",
            2 => "warn",
            _ => "info",
        };
        println!(
            "  {} {:<22} {:<10} {:<7} {}",
            marker(kind).style(st),
            h.api.style(st).bold(),
            format!("{} site{}", h.sites.len(), plural(h.sites.len())).style(faint()),
            h.origin().style(faint()),
            h.note.style(faint()),
        );

        if h.is_unreferenced() {
            println!(
                "  {:<4}{}",
                "",
                "present but no call site recovered".style(faint())
            );
            continue;
        }
        // A long tail of call sites buries the rest of the report, so the
        // default shows enough to start on and `--all` shows the whole list.
        let cap = if all { usize::MAX } else { 6 };
        for s in h.sites.iter().take(cap) {
            let at = s.from + an.display_base;
            let site = match &s.in_func {
                Some(f) if s.at_off > 0 => format!("{f}+0x{:x}", s.at_off),
                Some(f) => f.clone(),
                None => "-".into(),
            };
            println!(
                "  {:<4}{}  {}",
                "",
                format!("0x{at:x}").style(faint()),
                site.style(muted())
            );
        }
        if h.sites.len() > cap {
            println!(
                "  {:<4}{}",
                "",
                format!("… and {} more (--all)", h.sites.len() - cap).style(faint())
            );
        }
    }

    if an.truncated {
        println!(
            "  {}",
            "analysis budget reached, call sites may be incomplete".style(amber())
        );
    }
    Ok(())
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn cmd_audit(file: &str, reachable_only: bool, as_json: bool, db_path: Option<&str>) -> Result<()> {
    let s = Session::open(file, db_path, ANALYSIS_BUDGET, "the bug audit")?;
    if !matches!(s.bin.arch, model::Arch::X86 | model::Arch::X86_64) {
        anyhow::bail!(
            "argument analysis is x86/x64 only; this is {}",
            s.bin.arch.label()
        );
    }
    let mut findings = analysis::audit::run(&s.an, &s.bin, &s.bytes);
    if reachable_only {
        findings.retain(|f| f.reachable);
    }

    if as_json {
        let out: Vec<_> = findings
            .iter()
            .map(|f| {
                json!({
                    "addr": f.addr,
                    "func": f.func,
                    "api": f.api,
                    "pattern": f.pattern,
                    "severity": f.severity,
                    "reachable": f.reachable,
                    "detail": f.detail,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    section_header(&format!("audit ({} findings)", findings.len()));
    if findings.is_empty() {
        println!(
            "  {}",
            "no argument pattern looked exploitable".style(faint())
        );
        println!(
            "  {}",
            "this is not a clean bill; it is the absence of the patterns knife checks"
                .style(faint())
        );
        return Ok(());
    }

    for f in &findings {
        let (st, kind) = match f.severity {
            3 => (red(), "bad"),
            2 => (amber(), "warn"),
            _ => (muted(), "info"),
        };
        let site = match &f.func {
            Some(name) => name.clone(),
            None => "-".into(),
        };
        let reach = if f.reachable {
            "  ← reachable".style(red()).to_string()
        } else {
            String::new()
        };
        println!(
            "  {} {:<16} {:<24} {}{}",
            marker(kind).style(st),
            f.pattern.style(st).bold(),
            format!("{}  {}", f.api, site).style(muted()),
            format!("@ 0x{:x}", f.addr).style(faint()),
            reach,
        );
        println!("  {:<4}{}", "", f.detail.style(faint()));
    }

    if s.an.truncated {
        println!(
            "  {}",
            "analysis budget reached, findings may be incomplete".style(amber())
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
    section_header(&format!("indicators ({}), defanged", iocs.len()));
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

/// Recover what a driver exposes: devices, IRP dispatch, IOCTLs, primitives.
fn cmd_drv(file: &str, reachable_only: bool, as_json: bool, db_path: Option<&str>) -> Result<()> {
    let s = Session::open(file, db_path, ANALYSIS_BUDGET, "driver analysis")?;
    let an = &s.an;
    let strings = listing::string_map(&s.bin, &s.bytes, engine::display_base(&s.bin));
    let mut rep = driver::report(&s.bin, &s.bytes, an, &strings);
    if reachable_only {
        rep.primitives.retain(|p| p.reachable);
    }

    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep)?);
        return Ok(());
    }

    // Every report address is already in the engine's display space; the tag
    // and mode line are the only decoration needed.
    let tag = if rep.is_driver {
        "driver"
    } else {
        "not a driver"
    };
    let tag_color = if rep.is_driver { accent() } else { muted() };
    section_header(&format!(
        "{} {} · {} · {} · entry {}",
        rep.module.style(tag_color).bold(),
        tag.style(tag_color),
        rep.bits,
        rep.subsystem.unwrap_or_else(|| "no subsystem".into()),
        format!("0x{:x}", rep.entry).style(accent()),
    ));
    if !rep.why.is_empty() {
        println!("  {} {}", "why:".style(faint()), rep.why.join(", "));
    }

    if !rep.kernel_imports.is_empty() {
        let k = rep
            .kernel_imports
            .iter()
            .map(|(m, c)| format!("{} (x{c})", m.style(faint())))
            .collect::<Vec<_>>()
            .join(" · ");
        println!("  {} {}", "kernel imports:".style(faint()), k);
    }
    if !rep.app_imports.is_empty() {
        println!(
            "  {} {}",
            "app-layer imports:".style(faint()),
            rep.app_imports.join(", ").style(muted())
        );
    }

    // devices
    section_header(&format!("devices & symlinks ({})", rep.devices.len()));
    for d in &rep.devices {
        let x = if d.xrefs == 0 && !d.created {
            "unreferenced".to_owned()
        } else if d.created {
            format!("{} xrefs · created", d.xrefs)
        } else {
            format!("{} xrefs", d.xrefs)
        };
        println!(
            "  {}  {}  {}  {}",
            format!("0x{:x}", d.addr).style(faint()),
            d.name.style(accent()),
            (if d.wide { "wide" } else { "ascii" }).style(muted()),
            x.style(faint())
        );
    }
    if rep.devices.is_empty() {
        println!(
            "  {}",
            "no \\Device\\ or \\DosDevices\\ strings".style(faint())
        );
    }

    // IRP dispatch
    section_header(&format!("irp dispatch ({})", rep.irp.len()));
    for h in &rep.irp {
        println!(
            "  {}  {}  -> {}",
            format!("0x{:02x}", h.major).style(faint()),
            h.name.style(accent()),
            format!("0x{:x}", h.addr).style(faint())
        );
    }
    if rep.irp.is_empty() {
        println!("  {}", "no dispatch-table stores recovered".style(faint()));
    }

    // IOCTLs
    section_header(&format!("ioctl surface ({})", rep.ioctls.len()));
    for i in &rep.ioctls {
        let mcol = if i.method_code == 3 { red() } else { accent() };
        println!(
            "  {:<12} dev={:<5} fn={:<5} {} access={}  {}",
            format!("0x{:08x}", i.code).style(mcol),
            i.device_type,
            i.function,
            i.method.style(muted()),
            i.access,
            format!("@0x{:x}", i.addr).style(faint())
        );
    }
    if rep.ioctls.is_empty() {
        println!(
            "  {}",
            "no CTL_CODE compares recovered (entry may be indirect)".style(faint())
        );
    }

    // primitives
    section_header(&format!("kernel primitives ({})", rep.primitives.len()));
    for p in &rep.primitives {
        let sites = p
            .sites
            .iter()
            .map(|s| {
                let f = s.in_func.clone().unwrap_or_else(|| "?".into());
                format!("{} @0x{:x}", f, s.from)
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {}  {:<14} sev{}  {}",
            p.api.style(if p.severity >= 3 { red() } else { accent() }),
            format!("[{}]", p.class).style(muted()),
            p.severity,
            sites.style(faint())
        );
    }
    if rep.primitives.is_empty() {
        println!(
            "  {}",
            "no kernel-catalog primitives referenced".style(faint())
        );
    }

    // signing + known-bad
    section_header(&format!("signing ({} entries)", rep.signing.entries));
    if rep.signing.signed {
        if rep.signing.subjects.is_empty() {
            println!("  {}", "signed; no Common Name recovered".style(faint()));
        }
        for who in rep.signing.subjects.iter().take(4) {
            println!("  {} {}", "signed by".style(faint()), who.style(muted()));
        }
        for tp in rep.signing.thumbprints.iter().take(3) {
            println!("  {} {}", "  thumbprint".style(faint()), tp.style(faint()));
        }
    } else {
        println!("  {}", "unsigned / no Authenticode table".style(faint()));
    }

    if !rep.known_bad.is_empty() {
        section_header(&format!(
            "known vulnerable driver ({})",
            rep.known_bad.len()
        ));
        for k in &rep.known_bad {
            let order = if k.malicious {
                "malicious"
            } else {
                "vulnerable"
            };
            println!(
                "  {} {}  {} · {}",
                "[!]".style(red()).bold(),
                k.file.style(red()),
                order.style(red()),
                k.category.style(muted())
            );
            if !k.vendor.is_empty() {
                println!("      {} {}", "vendor:".style(faint()), k.vendor);
            }
            if !k.product.is_empty() {
                println!("      {} {}", "product:".style(faint()), k.product);
            }
        }
    }

    Ok(())
}

fn cmd_dis(
    file: &str,
    count: usize,
    vaddr: Option<String>,
    off: Option<String>,
    func: Option<String>,
    db_path: Option<&str>,
) -> Result<()> {
    // Function mode: recover the CFG and print the whole function with labels,
    // resolved call targets, cross-references, and your notes.
    if let Some(sel) = func {
        let sess = Session::open(file, db_path, ANALYSIS_BUDGET, "disassembly")?;
        return dis_function(&sess, &sel);
    }

    let bytes = load(file)?;
    let bin = parse(file, &bytes)?;
    if !disasm::supported(bin.arch) {
        anyhow::bail!(
            "disassembly supports x86/x64 and AArch64; this is {}",
            bin.arch.label()
        );
    }
    if off.is_some() && vaddr.is_some() {
        anyhow::bail!("--off and --vaddr are mutually exclusive; pass one");
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
    let insns = disasm::disassemble(&bytes, foff, va, bin.bits, bin.arch, count);
    print_disasm(&insns);
    Ok(())
}

/// One reference, rendered the same way whatever it points at.
fn print_xref(an: &engine::Analysis, x: &engine::Xref) {
    let from = x.from + an.display_base;
    let site = match an.function_at(x.from) {
        Some(f) => {
            let off = x.from.saturating_sub(f.addr);
            if off == 0 {
                f.name.clone()
            } else {
                format!("{}+0x{off:x}", f.name)
            }
        }
        None => "-".to_string(),
    };
    let st = match x.kind {
        engine::XrefKind::Call => mint(),
        engine::XrefKind::Data => muted(),
        _ => amber(),
    };
    println!(
        "  {}  {:<7} {}",
        format!("0x{from:x}").style(faint()),
        x.kind.label().style(st),
        site,
    );
}

fn cmd_xrefs(
    file: &str,
    target: Option<&str>,
    needle: Option<&str>,
    as_json: bool,
    db_path: Option<&str>,
) -> Result<()> {
    let sess = Session::open(file, db_path, ANALYSIS_BUDGET, "cross-references")?;
    let (an, bin, bytes) = (&sess.an, &sess.bin, &sess.bytes);
    let base = engine::display_base(bin);

    // String mode: locate the literals, then ask what points at them.
    if let Some(needle) = needle {
        let lower = needle.to_lowercase();
        let mut rows = Vec::new();
        for s in strs::extract_located(bytes, 4) {
            if !s.text.to_lowercase().contains(&lower) {
                continue;
            }
            let Some(va) = engine::off_to_va(bin, base, s.off) else {
                continue;
            };
            let Some(refs) = an.xrefs_to.get(&va) else {
                continue;
            };
            rows.push((va, s, refs));
        }

        if as_json {
            let out: Vec<_> = rows
                .iter()
                .map(|(va, s, refs)| {
                    json!({
                        "addr": va, "text": s.text, "wide": s.wide,
                        "refs": refs.iter().map(|x| json!({
                            "from": x.from + an.display_base,
                            "kind": x.kind.label(),
                            "in": an.function_at(x.from).map(|f| f.name.clone()),
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out)?);
            return Ok(());
        }

        section_header(&format!("strings matching '{needle}', referenced"));
        if rows.is_empty() {
            println!(
                "  {}",
                "no referenced string matched (unreferenced strings are not listed)".style(faint())
            );
            return Ok(());
        }
        for (va, s, refs) in &rows {
            println!(
                "  {}  {}",
                format!("0x{va:x}").style(accent()),
                format!("{:?}", s.text).style(muted())
            );
            for x in refs.iter() {
                print_xref(an, x);
            }
        }
        return Ok(());
    }

    let Some(target) = target else {
        anyhow::bail!("give a symbol, an address, or --str <text>");
    };

    let addrs = an.resolve(target, parse_num(target).ok());
    if addrs.is_empty() {
        anyhow::bail!("nothing named '{target}' (try `knife funcs` or `knife imports`)");
    }

    if as_json {
        let out: Vec<_> = addrs
            .iter()
            .map(|a| {
                let refs = an.xrefs_to.get(a).map(Vec::as_slice).unwrap_or(&[]);
                json!({
                    "addr": a + an.display_base,
                    "name": an.label(*a),
                    "refs": refs.iter().map(|x| json!({
                        "from": x.from + an.display_base,
                        "kind": x.kind.label(),
                        "in": an.function_at(x.from).map(|f| f.name.clone()),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let total: usize = addrs
        .iter()
        .map(|a| an.xrefs_to.get(a).map_or(0, Vec::len))
        .sum();
    section_header(&format!("xrefs to {target} ({total})"));

    for a in &addrs {
        let shown = a + an.display_base;
        println!(
            "  {} {}",
            format!("0x{shown:x}").style(accent()),
            an.label(*a).style(mint())
        );
        match an.xrefs_to.get(a) {
            Some(refs) => {
                for x in refs {
                    print_xref(an, x);
                }
            }
            None => println!("  {}", "no references".style(faint())),
        }
    }
    if an.truncated {
        println!(
            "  {}",
            "analysis budget reached, references may be incomplete".style(amber())
        );
    }
    Ok(())
}

fn cmd_paths(
    file: &str,
    target: &str,
    from: Option<&str>,
    max: usize,
    as_json: bool,
    db_path: Option<&str>,
) -> Result<()> {
    let sess = Session::open(file, db_path, ANALYSIS_BUDGET, "call-graph search")?;
    let (an, bin) = (&sess.an, &sess.bin);

    let targets = an.resolve(target, parse_num(target).ok());
    if targets.is_empty() {
        anyhow::bail!("nothing named '{target}' (try `knife funcs` or `knife imports`)");
    }

    // Roots are the places control enters from outside: the entry point and
    // every export. Narrowing with --from asks the more specific question,
    // "is it reachable from *this* function".
    let roots: Vec<u64> = match from {
        Some(f) => {
            let r = an.resolve(f, parse_num(f).ok());
            if r.is_empty() {
                anyhow::bail!("no function '{f}' to start from");
            }
            r
        }
        None => {
            let base = engine::display_base(bin);
            let mut r: Vec<u64> = bin
                .symbols
                .iter()
                .filter(|s| s.kind == model::SymKind::Export)
                .map(|s| s.addr + base)
                .collect();
            r.push(bin.entry + base);
            r
        }
    };

    let mut chains: Vec<Vec<u64>> = Vec::new();
    for t in &targets {
        chains.extend(an.paths_to(*t, &roots, max, from.is_some()));
        if chains.len() >= max {
            break;
        }
    }
    chains.sort_by_key(|c| c.len());
    chains.truncate(max);

    if as_json {
        let out: Vec<_> = chains
            .iter()
            .map(|c| {
                c.iter()
                    .map(|a| json!({"addr": a + an.display_base, "name": an.label(*a)}))
                    .collect::<Vec<_>>()
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    section_header(&format!("paths to {target} ({})", chains.len()));
    if chains.is_empty() {
        let origin = match from {
            Some(f) => format!("no call chain from {f} reaches it"),
            None => "no call chain from an entry point or export reaches it".to_string(),
        };
        println!("  {}", origin.style(faint()));
        println!(
            "  {}",
            "it may be reached indirectly, which static analysis cannot follow".style(faint())
        );
        return Ok(());
    }

    for c in &chains {
        println!();
        for (i, a) in c.iter().enumerate() {
            let shown = a + an.display_base;
            let arrow = if i == 0 { " " } else { "→" };
            let st = if i + 1 == c.len() { red() } else { muted() };
            println!(
                "  {}{}  {} {}",
                "  ".repeat(i.min(8)),
                arrow.style(faint()),
                format!("0x{shown:x}").style(faint()),
                an.label(*a).style(st),
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_graph(
    file: &str,
    function: Option<&str>,
    from: &[String],
    reachable: bool,
    as_dot: bool,
    as_json: bool,
    db_path: Option<&str>,
) -> Result<()> {
    if as_dot && as_json {
        anyhow::bail!("choose either --dot or --json, not both")
    }
    if function.is_some() && (!from.is_empty() || reachable) {
        anyhow::bail!("--func exports a CFG and cannot be combined with --from or --reachable")
    }
    let sess = Session::open(file, db_path, ANALYSIS_BUDGET, "graph recovery")?;
    let an = &sess.an;
    let resolve_function = |selector: &str| {
        if let Some(function) = an.find_by_name(selector) {
            Some(function)
        } else if let Ok(value) = parse_num(selector) {
            let internal = value.checked_sub(an.display_base).unwrap_or(value);
            an.find_function(internal)
                .or_else(|| an.find_function(value))
        } else {
            None
        }
    };

    let (mut graph, title) = if let Some(selector) = function {
        let function = resolve_function(selector)
            .with_context(|| format!("no function '{selector}' (try `knife funcs`)"))?;
        (
            analysis::graphs::cfg(function),
            format!("CFG: {}", function.name),
        )
    } else {
        let mut roots = BTreeSet::new();
        for selector in from {
            let function = resolve_function(selector)
                .with_context(|| format!("no function '{selector}' to use as a graph root"))?;
            roots.insert(function.addr);
        }
        if reachable {
            let base = engine::display_base(&sess.bin);
            roots.insert(sess.bin.entry + base);
            roots.extend(
                sess.bin
                    .symbols
                    .iter()
                    .filter(|symbol| symbol.kind == model::SymKind::Export)
                    .map(|symbol| symbol.addr + base),
            );
        }
        let scoped = (!roots.is_empty()).then_some(&roots);
        (
            analysis::graphs::call_graph(&an.functions, &an.imports, scoped),
            if roots.is_empty() {
                "Call graph".into()
            } else {
                format!("Call graph: {} root{}", roots.len(), plural(roots.len()))
            },
        )
    };
    graph.add_display_base(an.display_base);

    if as_dot {
        print!("{}", analysis::graphs::dot(&graph, &title));
        return Ok(());
    }
    if as_json {
        println!("{}", serde_json::to_string_pretty(&graph)?);
        return Ok(());
    }

    section_header(&format!(
        "{} ({} node{}, {} edge{})",
        title,
        graph.nodes.len(),
        plural(graph.nodes.len()),
        graph.edges.len(),
        plural(graph.edges.len())
    ));
    let labels: BTreeMap<&str, &str> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.label.as_str()))
        .collect();
    for node in &graph.nodes {
        println!(
            "  {}  {:<10} {:<28} {}",
            format!("0x{:x}", node.address).style(faint()),
            node.kind.style(amber()),
            node.label.style(mint()),
            node.detail.as_deref().unwrap_or("").style(muted())
        );
    }
    if !graph.edges.is_empty() {
        println!();
        println!("  {}", "edges".style(amber()).bold());
        for edge in &graph.edges {
            println!(
                "  {:<28} {} {:<28} {}{}",
                labels
                    .get(edge.from.as_str())
                    .copied()
                    .unwrap_or(&edge.from),
                "→".style(accent()),
                labels.get(edge.to.as_str()).copied().unwrap_or(&edge.to),
                edge.kind.style(faint()),
                if edge.back { " ↶" } else { "" }
            );
        }
    }
    if an.truncated {
        println!(
            "  {}",
            "analysis budget reached, graph may be incomplete".style(amber())
        );
    }
    Ok(())
}

fn cmd_funcs(file: &str, by_refs: bool, as_json: bool, db_path: Option<&str>) -> Result<()> {
    let sess = Session::open(file, db_path, ANALYSIS_BUDGET, "control-flow analysis")?;
    let an = &sess.an;

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
                    "tables": f.tables.len(),
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
            "analysis budget reached, listing is partial".style(amber())
        );
    }
    Ok(())
}

fn dis_function(sess: &Session, sel: &str) -> Result<()> {
    let an = &sess.an;

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

    // The listing model is shared with the interactive view, so the two can
    // never drift into showing different things.
    let strings = listing::string_map(&sess.bin, &sess.bytes, sess.an.display_base);
    let hints = if driver::plausibly_a_driver(&sess.bin) {
        driver::listing_hints(&sess.bin, &sess.bytes, &sess.an)
    } else {
        BTreeMap::new()
    };
    for line in listing::function(
        an,
        func,
        &sess.db,
        engine::display_base(&sess.bin),
        &strings,
        Some(&hints),
    ) {
        match line {
            listing::Line::Label { text, .. } => println!("  {}:", text.style(amber())),
            listing::Line::Data { text, .. } => println!("  {}", text.style(muted())),
            listing::Line::Insn {
                addr,
                mnemonic,
                operands,
                annot,
                ..
            } => {
                let a = addr + an.display_base;
                let annot = match annot {
                    Some(listing::Annot::Note(t)) => format!("  ; {t}").style(amber()).to_string(),
                    Some(listing::Annot::Symbol(t)) => format!("  ; {t}").style(mint()).to_string(),
                    Some(listing::Annot::Local(t)) => format!("  ; {t}").style(faint()).to_string(),
                    Some(listing::Annot::Text(t)) => {
                        format!("  ; \"{t}\"").style(amber()).to_string()
                    }
                    Some(listing::Annot::Hint(t)) => format!("  ; {t}").style(faint()).to_string(),
                    None => String::new(),
                };
                println!(
                    "  {}  {} {}{}",
                    format!("{a:012x}").style(faint()),
                    mnemonic.style(accent()),
                    operands.style(muted()),
                    annot,
                );
            }
        }
    }
    Ok(())
}

fn cmd_pseudo(file: &str, sel: &str, db_path: Option<&str>) -> Result<()> {
    let sess = Session::open(file, db_path, ANALYSIS_BUDGET, "the pseudocode view")?;
    let an = &sess.an;

    let func = if let Some(f) = an.find_by_name(sel) {
        Some(f)
    } else if let Ok(v) = parse_num(sel) {
        let internal = v.checked_sub(an.display_base).unwrap_or(v);
        an.find_function(internal).or_else(|| an.find_function(v))
    } else {
        None
    };
    let func = func.with_context(|| format!("no function '{sel}' (try `knife funcs`)"))?;

    section_header(&format!(
        "pseudocode: {} @ 0x{:x}",
        func.name,
        func.addr + an.display_base
    ));
    let strings = listing::string_map(&sess.bin, &sess.bytes, engine::display_base(&sess.bin));
    for line in analysis::ir::decompile(an, &sess.bin, func, &strings, &sess.db) {
        // Labels and the function braces sit at the margin; statements indent.
        if line.label {
            println!("  {}", line.text.style(accent()));
        } else {
            let comment = line.text.trim_start().starts_with("/*");
            println!(
                "      {}",
                if comment {
                    line.text.style(faint()).to_string()
                } else {
                    line.text.style(muted()).to_string()
                }
            );
        }
    }
    println!();
    println!(
        "  {}",
        "pseudocode is a lossy view; `knife dis` shows the exact instructions".style(faint())
    );
    Ok(())
}

fn cmd_hex(file: &str, off: u64, len: usize) -> Result<()> {
    let bytes = load(file)?;
    let start = off as usize;
    if start >= bytes.len() {
        anyhow::bail!("offset 0x{off:x} past end of file ({})", bytes.len());
    }
    let end = start.saturating_add(len).min(bytes.len());
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

    section_header(&format!("yara: {} matched", matches.len()));
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

fn cmd_diff(a: &str, b: &str) -> Result<bool> {
    let bytes_a = load(a)?;
    let bin_a = parse(a, &bytes_a)?;
    let bytes_b = load(b)?;
    let bin_b = parse(b, &bytes_b)?;
    let (lines, changed) = diff_binaries(&bin_a, &bytes_a, &bin_b, &bytes_b);

    if changed.is_empty() {
        println!(
            "  {}  {} and {} are identical",
            "no change".style(mint()),
            basename(a),
            basename(b)
        );
        return Ok(false);
    }

    println!(
        "  differences between {} and {}",
        basename(a).style(faint()),
        basename(b).style(faint())
    );
    for l in &lines {
        let (mark, rest) = l.split_once(' ').unwrap_or(("", l.as_str()));
        match mark {
            "+" => println!("  {} {}", "+".style(mint()), rest.style(mint())),
            "-" => println!("  {} {}", "-".style(red()), rest.style(red())),
            "~" => println!("  {} {}", "~".style(amber()), rest.style(amber())),
            _ => println!("  {l}"),
        }
    }
    println!(
        "  {} category(ies) changed: {}",
        changed.len(),
        changed.join(", ")
    );
    Ok(true)
}

/// The engine of `knife diff`, kept free of any I/O so it is unit-testable:
/// same address → compared; same name → compared; a single edited byte inside
/// a function body counts as a change even when nothing else moved.
fn diff_binaries(
    bin_a: &model::Binary,
    bytes_a: &[u8],
    bin_b: &model::Binary,
    bytes_b: &[u8],
) -> (Vec<String>, Vec<String>) {
    let an_a = engine::analyze(bin_a, bytes_a, 500_000, &db::Db::default());
    let an_b = engine::analyze(bin_b, bytes_b, 500_000, &db::Db::default());

    // Lines of `+`/`-`/`~` marked output, plus the categories that changed.
    let mut lines: Vec<String> = Vec::new();
    let mut changed: Vec<String> = Vec::new();

    // ── the container itself ──
    let arch_a = format!("{:?} {}", bin_a.arch, bin_a.bits);
    let arch_b = format!("{:?} {}", bin_b.arch, bin_b.bits);
    if arch_a != arch_b {
        changed.push("arch".into());
        lines.push(format!("~ arch: {arch_a}  →  {arch_b}"));
    }
    let ep_a = format!("0x{:x}", bin_a.entry + bin_a.image_base);
    let ep_b = format!("0x{:x}", bin_b.entry + bin_b.image_base);
    if ep_a != ep_b {
        changed.push("entry".into());
        lines.push(format!("~ entry point: {ep_a}  →  {ep_b}"));
    }

    // ── sections, keyed by name ──
    let sects_a: BTreeMap<&str, &model::Section> = bin_a
        .sections
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    let sects_b: BTreeMap<&str, &model::Section> = bin_b
        .sections
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    let all: BTreeSet<&str> = sects_a.keys().chain(sects_b.keys()).copied().collect();
    for name in all {
        match (sects_a.get(name), sects_b.get(name)) {
            (Some(x), Some(y)) => {
                let xk = format!("{:#x} {:#x} {}", x.vaddr, x.vsize, x.flags());
                let yk = format!("{:#x} {:#x} {}", y.vaddr, y.vsize, y.flags());
                if xk != yk {
                    changed.push("section".into());
                    lines.push(format!("~ section {name}: {xk}  →  {yk}"));
                }
            }
            (Some(x), None) => {
                changed.push("section".into());
                lines.push(format!(
                    "- section {name}: {:#x} {} {}",
                    x.vsize,
                    x.flags(),
                    human(x.file_size)
                ));
            }
            (None, Some(y)) => {
                changed.push("section".into());
                lines.push(format!(
                    "+ section {name}: {:#x} {} {}",
                    y.vsize,
                    y.flags(),
                    human(y.file_size)
                ));
            }
            _ => {}
        }
    }

    // ── imports, as (library!function) pairs ──
    let imports_a: BTreeSet<String> = bin_a
        .imports
        .iter()
        .flat_map(|lib| {
            lib.functions
                .iter()
                .map(move |f| format!("{}!{}", lib.name, f))
        })
        .collect();
    let imports_b: BTreeSet<String> = bin_b
        .imports
        .iter()
        .flat_map(|lib| {
            lib.functions
                .iter()
                .map(move |f| format!("{}!{}", lib.name, f))
        })
        .collect();
    for missing in imports_a.difference(&imports_b) {
        changed.push("import".into());
        lines.push(format!("- {missing}"));
    }
    for extra in imports_b.difference(&imports_a) {
        changed.push("import".into());
        lines.push(format!("+ {extra}"));
    }

    // ── functions ──
    let funcs_a: BTreeMap<u64, &engine::Function> = an_a
        .functions
        .iter()
        .map(|f| (f.addr + an_a.display_base, f))
        .collect();
    let funcs_b: BTreeMap<u64, &engine::Function> = an_b
        .functions
        .iter()
        .map(|f| (f.addr + an_b.display_base, f))
        .collect();
    let addrs: BTreeSet<u64> = funcs_a.keys().chain(funcs_b.keys()).copied().collect();
    for va in addrs {
        match (funcs_a.get(&va), funcs_b.get(&va)) {
            (None, None) => {}
            (None, Some(f)) => {
                changed.push("func".into());
                lines.push(format!("+ {} at 0x{va:x}", f.name));
            }
            (Some(f), None) => {
                changed.push("func".into());
                lines.push(format!("- {} at 0x{va:x}", f.name));
            }
            (Some(x), Some(y)) => {
                let renamed = x.named && y.named && x.name != y.name;
                let body_changed = x.body_hash() != y.body_hash();
                if x.size != y.size || renamed || body_changed {
                    changed.push("func".into());
                    let mut detail = format!("size {}  →  {}", x.size, y.size);
                    if renamed {
                        detail.push_str(&format!(" (now {})", y.name));
                    }
                    if body_changed {
                        detail.push_str(", body changed");
                    }
                    lines.push(format!("~ {} at 0x{va:x}: {detail}", x.name));
                }
            }
        }
    }

    // ── the raw bytes, as a guard when the structural picture is empty ──
    // Files with no sections (hand-built or truncated) compare as identical
    // even when a byte flipped; the digest below makes that a change. When
    // sections/functions already differ this is redundant, so it stays quiet.
    if changed.is_empty() {
        let ra = rolling_hash_bytes(bytes_a);
        let rb = rolling_hash_bytes(bytes_b);
        if bytes_a.len() != bytes_b.len() {
            changed.push("size".into());
            lines.push(format!(
                "~ size: {} → {} bytes",
                bytes_a.len(),
                bytes_b.len()
            ));
        } else if ra != rb {
            changed.push("raw".into());
            lines.push("~ raw byte content differs, outside named sections".into());
        }
    }

    (lines, changed)
}

/// A cheap deterministic digest of the whole file, so the guard above needs
/// no new crate. Collisions are irrelevant here: it pairs two files only.
fn rolling_hash_bytes(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, &b) in bytes.iter().enumerate() {
        h ^= u64::from(b);
        h = h.rotate_left(13);
        h ^= (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    h
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

fn parse_signed_num(s: &str) -> Result<i64> {
    let text = s.trim();
    if let Some(rest) = text.strip_prefix('-') {
        let magnitude = parse_num(rest)?;
        Ok(i64::try_from(magnitude)?
            .checked_neg()
            .context("offset is out of range")?)
    } else {
        Ok(i64::try_from(parse_num(text)?)?)
    }
}

fn contains_identifier(text: &str, identifier: &str) -> bool {
    text.split(|ch: char| ch != '_' && !ch.is_ascii_alphanumeric())
        .any(|token| token == identifier)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::fixture;

    /// A raw x86-64 code blob mapped at `vaddr`, exec, nothing else. The
    /// minimal shape both sides of a diff can share.
    fn code_at(vaddr: u64, code: &[u8]) -> (model::Binary, Vec<u8>) {
        let mut bin = model::Binary::stub(model::Format::Elf, model::Arch::X86_64);
        bin.entry = vaddr;
        bin.sections = vec![model::Section {
            name: ".text".into(),
            vaddr,
            vsize: code.len() as u64,
            file_off: vaddr,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let mut bytes = vec![0u8; vaddr as usize];
        bytes.extend_from_slice(code);
        (bin, bytes)
    }

    #[test]
    fn identical_binaries_report_no_change() {
        let code = [0x90, 0x90, 0xc3]; // nop; nop; ret
        let (a, ba) = code_at(0x1000, &code);
        let (b, bb) = code_at(0x1000, &code);
        let (lines, changed) = diff_binaries(&a, &ba, &b, &bb);
        assert!(changed.is_empty(), "unexpected: {changed:?}");
        assert!(lines.is_empty(), "unexpected: {lines:?}");
    }

    #[test]
    fn a_single_edited_byte_flags_the_body_even_when_the_size_matches() {
        // Same length, same frames: only one nop became an int3.
        let a = [0x90, 0x90, 0x90, 0xc3];
        let b = [0x90, 0xcc, 0x90, 0xc3];
        let (x, bx) = code_at(0x1000, &a);
        let (y, by) = code_at(0x1000, &b);
        let (lines, changed) = diff_binaries(&x, &bx, &y, &by);
        let func_lines: Vec<_> = lines.iter().filter(|l| l.starts_with('~')).collect();
        assert_eq!(func_lines.len(), 1, "one function moved: {lines:?}");
        assert!(func_lines[0].contains("body changed"), "{func_lines:?}");
        assert!(changed.contains(&"func".to_string()), "{changed:?}");
    }

    #[test]
    fn a_byte_flip_outside_any_sections_is_still_a_change() {
        // No sections at all, no bytes decoded into functions: only the raw
        // guard can see this difference.
        let mut a =
            crate::model::Binary::stub(crate::model::Format::Elf, crate::model::Arch::X86_64);
        let mut b =
            crate::model::Binary::stub(crate::model::Format::Elf, crate::model::Arch::X86_64);
        a.entry = 0x1000;
        b.entry = 0x1000;
        let (lines, changed) = diff_binaries(&a, b"\x90\xc3", &b, b"\xcc\xc3");
        assert!(changed.contains(&"raw".to_string()), "{changed:?}");
        assert!(
            lines.iter().any(|l| l.contains("raw byte content differs")),
            "{lines:?}"
        );
    }

    #[test]
    fn imports_are_compared_across_formats() {
        let a_bytes = fixture::pe_with_iat_call();
        let b_bytes = fixture::elf_with_plt_call();
        let a = crate::formats::analyze("a", &a_bytes).unwrap();
        let b = crate::formats::analyze("b", &b_bytes).unwrap();
        let (lines, changed) = diff_binaries(&a, &a_bytes, &b, &b_bytes);
        assert!(!changed.is_empty(), "a PE and an ELF must differ");
        let all = lines.join("\n");
        assert!(all.contains("kernel32.dll!ExitProcess"), "{all}");
        assert!(all.contains("strcpy"), "{all}");
        assert!(all.contains("section .text"), "{all}");
    }

    #[test]
    fn field_and_type_commands_parse_the_documented_workflow() {
        let field = Cli::try_parse_from([
            "knife",
            "field",
            "sample.exe",
            "--type",
            "CONTEXT",
            "0x18",
            "length",
            "--data-type",
            "size_t",
        ])
        .unwrap();
        assert!(matches!(
            field.cmd,
            Command::Field {
                type_name,
                offset,
                name: Some(name),
                data_type: Some(data_type),
                clear: false,
                ..
            } if type_name == "CONTEXT" && offset == "0x18" && name == "length"
                && data_type == "size_t"
        ));

        let binding = Cli::try_parse_from([
            "knife",
            "type",
            "sample.exe",
            "--func",
            "parse_packet",
            "rcx",
            "CONTEXT",
        ])
        .unwrap();
        assert!(matches!(
            binding.cmd,
            Command::Type {
                func,
                base,
                type_name: Some(type_name),
                clear: false,
                ..
            } if func == "parse_packet" && base == "rcx" && type_name == "CONTEXT"
        ));

        let variable = Cli::try_parse_from([
            "knife",
            "var",
            "sample.exe",
            "--func",
            "parse_packet",
            "rcx",
            "request",
        ])
        .unwrap();
        assert!(matches!(
            variable.cmd,
            Command::Var {
                func,
                base,
                name: Some(name),
                clear: false,
                ..
            } if func == "parse_packet" && base == "rcx" && name == "request"
        ));

        let prototype = Cli::try_parse_from([
            "knife",
            "proto",
            "sample.exe",
            "--func",
            "parse_packet",
            "--returns",
            "bool",
            "--param",
            "CONTEXT *",
            "--param",
            "size_t",
        ])
        .unwrap();
        assert!(matches!(
            prototype.cmd,
            Command::Proto {
                func,
                returns: Some(returns),
                params,
                clear: false,
                ..
            } if func == "parse_packet"
                && returns == "bool"
                && params == ["CONTEXT *", "size_t"]
        ));

        let library = Cli::try_parse_from([
            "knife",
            "typelib",
            "sample.exe",
            "--import",
            "windows-kernel.json",
            "--replace",
        ])
        .unwrap();
        assert!(matches!(
            library.cmd,
            Command::TypeLib {
                import: Some(path),
                export: None,
                replace: true,
                ..
            } if path == "windows-kernel.json"
        ));
    }

    #[test]
    fn signed_field_offsets_accept_hex_and_decimal() {
        assert_eq!(parse_signed_num("0x18").unwrap(), 0x18);
        assert_eq!(parse_signed_num("-0x8").unwrap(), -8);
        assert_eq!(parse_signed_num("-16").unwrap(), -16);
    }

    #[test]
    fn graph_command_parses_cfg_and_rooted_callgraph_modes() {
        let cfg = Cli::try_parse_from([
            "knife",
            "graph",
            "sample.exe",
            "--func",
            "parse_packet",
            "--dot",
        ])
        .unwrap();
        assert!(matches!(
            cfg.cmd,
            Command::Graph {
                func: Some(func),
                dot: true,
                reachable: false,
                ..
            } if func == "parse_packet"
        ));

        let calls = Cli::try_parse_from([
            "knife",
            "graph",
            "sample.exe",
            "--from",
            "entry",
            "--from",
            "dispatch",
            "--reachable",
        ])
        .unwrap();
        assert!(matches!(
            calls.cmd,
            Command::Graph {
                func: None,
                from,
                reachable: true,
                dot: false,
                ..
            } if from == ["entry", "dispatch"]
        ));
    }

    #[test]
    fn patch_command_parses_virtual_offset_clear_and_export_modes() {
        let stage = Cli::try_parse_from([
            "knife",
            "patch",
            "sample.exe",
            "--vaddr",
            "0x401000",
            "--bytes",
            "90 90 cc",
        ])
        .unwrap();
        assert!(matches!(
            stage.cmd,
            Command::Patch {
                vaddr: Some(address),
                off: None,
                bytes: Some(bytes),
                clear: false,
                ..
            } if address == "0x401000" && bytes == "90 90 cc"
        ));

        let clear = Cli::try_parse_from([
            "knife",
            "patch",
            "sample.exe",
            "--off",
            "0x400",
            "--clear",
            "--len",
            "3",
        ])
        .unwrap();
        assert!(matches!(
            clear.cmd,
            Command::Patch {
                off: Some(offset),
                clear: true,
                len: Some(3),
                ..
            } if offset == "0x400"
        ));

        let export = Cli::try_parse_from([
            "knife",
            "patch",
            "sample.exe",
            "--export",
            "patched.exe",
            "--force",
        ])
        .unwrap();
        assert!(matches!(
            export.cmd,
            Command::Patch {
                export: Some(output),
                force: true,
                ..
            } if output == "patched.exe"
        ));
    }

    #[test]
    fn patch_command_stages_feeds_analysis_exports_and_restores() {
        let root =
            std::env::temp_dir().join(format!("knife-command-patch-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("fixture.elf");
        let database = root.join("fixture.json");
        let output = root.join("fixture-patched.elf");
        let original = fixture::elf_with_plt_call();
        std::fs::write(&input, &original).unwrap();
        let bin = formats::analyze("fixture.elf", &original).unwrap();
        let offset = engine::va_to_off(&bin, engine::display_base(&bin), bin.entry)
            .expect("fixture entry file offset");
        let replacement = original[offset] ^ 1;
        let offset_text = format!("0x{offset:x}");
        let bytes_text = format!("{replacement:02x}");
        let input_text = input.to_string_lossy();
        let db_text = database.to_string_lossy();

        cmd_patch(
            &input_text,
            PatchArgs {
                vaddr: None,
                off: Some(&offset_text),
                bytes: Some(&bytes_text),
                clear: false,
                len: None,
                export: None,
                force: false,
            },
            false,
            Some(&db_text),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&input).unwrap(),
            original,
            "input stays immutable"
        );

        let session = Session::open(&input_text, Some(&db_text), 10_000, "test").unwrap();
        assert_eq!(session.bytes[offset], replacement);
        assert_eq!(session.db.patches.len(), 1);

        let output_text = output.to_string_lossy();
        cmd_patch(
            &input_text,
            PatchArgs {
                vaddr: None,
                off: None,
                bytes: None,
                clear: false,
                len: None,
                export: Some(&output_text),
                force: false,
            },
            false,
            Some(&db_text),
        )
        .unwrap();
        let exported = std::fs::read(&output).unwrap();
        assert_eq!(exported[offset], replacement);
        assert_eq!(exported.len(), original.len());

        cmd_patch(
            &input_text,
            PatchArgs {
                vaddr: None,
                off: Some(&offset_text),
                bytes: None,
                clear: true,
                len: None,
                export: None,
                force: false,
            },
            false,
            Some(&db_text),
        )
        .unwrap();
        let sha = hashes::sha256_hex(&original);
        let restored = db::Db::load(&sha, &input_text, Some(&db_text)).unwrap();
        assert!(restored.patches.is_empty());
        assert_eq!(restored.apply_patches(&original).unwrap(), original);
        let _ = std::fs::remove_dir_all(root);
    }
}
