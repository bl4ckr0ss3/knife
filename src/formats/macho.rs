//! Mach-O → Binary. Fat binaries: the first architecture slice is used.

use super::mk_section;
use crate::model::{Arch, Binary, Format, HardeningFacts, ImportedLib, SymKind, Symbol};
use anyhow::{bail, Result};
use goblin::mach::{Mach, MachO};

const CPU_ARCH_ABI64: u32 = 0x0100_0000;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_ARM: u32 = 12;

const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;

/// The architecture a Mach-O CPU type names.
fn arch_of(cputype: u32) -> Arch {
    let is64 = cputype & CPU_ARCH_ABI64 != 0;
    match cputype & !CPU_ARCH_ABI64 {
        CPU_TYPE_X86 if is64 => Arch::X86_64,
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_ARM if is64 => Arch::Aarch64,
        CPU_TYPE_ARM => Arch::Arm,
        _ => Arch::Other,
    }
}

pub fn build(path: &str, bytes: &[u8], mach: Mach) -> Result<Binary> {
    // A universal binary holds several images and only one can be analysed. The
    // first is taken, as before, but silently choosing between architectures is
    // how someone ends up reading the arm64 half of a file while believing they
    // are looking at the x86-64 one — so it is written down.
    //
    // Bounded, and in one pass. The slice count is a number in the file, and a
    // corrupt one can claim millions: walking all of them to list what is there
    // turns a fixed cost into whatever the input asks for, which for a tool
    // whose whole job is hostile input is not a listing feature but a way to be
    // stopped. A universal binary carries a handful of slices; reading more than
    // that says nothing extra.
    const MAX_SLICES: usize = 8;
    let (macho, note) = match mach {
        Mach::Binary(m) => (m, None),
        Mach::Fat(fat) => {
            let mut names: Vec<String> = Vec::new();
            let mut first: Option<MachO> = None;
            for slice in fat.into_iter().take(MAX_SLICES) {
                let Ok(goblin::mach::SingleArch::MachO(m)) = slice else {
                    continue;
                };
                names.push(arch_of(m.header.cputype).label().to_string());
                if first.is_none() {
                    first = Some(m);
                }
            }
            let Some(first) = first else {
                bail!("fat Mach-O: no usable architecture slice");
            };
            let note = (names.len() > 1).then(|| {
                format!(
                    "universal binary; analysing the first of {} slices ({})",
                    names.len(),
                    names.join(", ")
                )
            });
            (first, note)
        }
    };
    let mut out = build_one(path, bytes, macho);
    out.notes.extend(note);
    Ok(out)
}

fn build_one(path: &str, bytes: &[u8], m: MachO) -> Binary {
    let ct = m.header.cputype;
    let is64 = ct & CPU_ARCH_ABI64 != 0;
    let arch = arch_of(ct);

    let mut sections = Vec::new();
    for seg in &m.segments {
        let init = seg.initprot;
        if let Ok(secs) = seg.sections() {
            for (sec, _data) in secs {
                let name = format!(
                    "{},{}",
                    sec.segname().unwrap_or("?"),
                    sec.name().unwrap_or("?")
                );
                sections.push(mk_section(
                    name,
                    sec.addr,
                    sec.size,
                    sec.offset as u64,
                    sec.size,
                    init & VM_PROT_READ != 0,
                    init & VM_PROT_WRITE != 0,
                    init & VM_PROT_EXECUTE != 0,
                    bytes,
                ));
            }
        }
    }

    let import_fns: Vec<String> = m
        .imports()
        .map(|v| v.into_iter().map(|i| i.name.to_string()).collect())
        .unwrap_or_default();
    let imports = if import_fns.is_empty() {
        Vec::new()
    } else {
        vec![ImportedLib {
            name: "(dyld imports)".to_string(),
            functions: import_fns,
            ordinals: Vec::new(),
        }]
    };
    let exports: Vec<String> = m
        .exports()
        .map(|v| v.into_iter().map(|e| e.name).collect())
        .unwrap_or_default();

    // Mitigation facts. Mach-O keeps its hardening opt-ins in the header flags
    // word, with the code signature and the __RESTRICT segment as separate
    // load-command and segment evidence.
    let code_signature = m.load_commands.iter().any(|lc| {
        matches!(
            lc.command,
            goblin::mach::load_command::CommandVariant::CodeSignature(_)
        )
    });
    let restrict_segment = m
        .segments
        .iter()
        .any(|seg| seg.name().is_ok_and(|n| n.starts_with("__RESTRICT")));
    let stack_chk = imports
        .iter()
        .flat_map(|l| l.functions.iter())
        .any(|n| n.trim_start_matches('_').starts_with("stack_chk"));

    let mut notes = vec!["Mach-O".to_string()];
    notes.push(if is64 {
        "64-bit".into()
    } else {
        "32-bit".into()
    });

    // The symbol table goblin already parsed. PE and ELF both feed theirs to the
    // engine; Mach-O was discarding its own and analysing from the entry point
    // alone, so a binary with a full symbol table still read as `sub_…`
    // throughout. Defined symbols in a section are the ones with an address
    // worth having; undefined ones name imports and belong to the stub, not
    // here.
    let mut symbols: Vec<Symbol> = Vec::new();
    for sym in m.symbols() {
        let Ok((name, nl)) = sym else { continue };
        if nl.is_stab() || nl.is_undefined() || nl.n_value == 0 {
            continue;
        }
        if nl.get_type() != goblin::mach::symbols::N_SECT {
            continue;
        }
        let name = name.strip_prefix('_').unwrap_or(name);
        if name.is_empty() {
            continue;
        }
        symbols.push(Symbol {
            addr: nl.n_value,
            name: name.to_string(),
            kind: SymKind::Func,
            size: None,
        });
    }

    Binary {
        path: path.to_string(),
        size: bytes.len() as u64,
        format: Format::MachO,
        arch,
        bits: if is64 { 64 } else { 32 },
        endian_little: m.little_endian,
        is_lib: m.header.filetype == 6, // MH_DYLIB
        is_stripped: m.symbols.is_none(),
        entry: m.entry,
        image_base: 0,
        subsystem: None,
        timestamp: None,
        sections,
        imports,
        exports,
        symbols,
        func_hints: Vec::new(),
        libs: m.libs.iter().map(|s| s.to_string()).collect(),
        pointer_map: Vec::new(),
        rpaths: m.rpaths.iter().map(|s| s.to_string()).collect(),
        overall_entropy: 0.0,
        overlay_off: None,
        overlay_size: 0,
        overlay_entropy: 0.0,
        has_signature: code_signature,
        sig_region: None,
        // Mach-O debug info lives in a dSYM bundle, not a PDB.
        pdb: crate::formats::pdbsym::Pdb::NotReferenced,
        hardening: HardeningFacts {
            macho_flags: Some(m.header.flags),
            code_signature,
            restrict_segment,
            stack_chk,
            ..Default::default()
        },
        notes,
    }
}
