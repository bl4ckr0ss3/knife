//! ELF → Binary.

use super::mk_section;
use crate::model::{Arch, Binary, Format, HardeningFacts, ImportedLib, SymKind, Symbol};
use goblin::elf::Elf;

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 0x1;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const DF_1_PIE: u64 = 0x0800_0000;

pub fn build(path: &str, bytes: &[u8], elf: Elf) -> Binary {
    let arch = match elf.header.e_machine {
        3 => Arch::X86,
        62 => Arch::X86_64,
        40 => Arch::Arm,
        183 => Arch::Aarch64,
        8 => Arch::Mips,
        243 => Arch::Riscv,
        _ => Arch::Other,
    };

    let sections = elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_type != 0) // skip SHT_NULL
        .map(|sh| {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("(bad)")
                .to_string();
            let f = sh.sh_flags;
            let alloc = f & SHF_ALLOC != 0;
            mk_section(
                name,
                sh.sh_addr,
                sh.sh_size,
                sh.sh_offset,
                if sh.sh_type == 8 { 0 } else { sh.sh_size }, // SHT_NOBITS (.bss) has no file bytes
                alloc,
                f & SHF_WRITE != 0,
                f & SHF_EXECINSTR != 0,
                bytes,
            )
        })
        .collect();

    // Imports: undefined dynamic symbols. Exports: defined global dynamic symbols.
    let mut imports_fns: Vec<String> = Vec::new();
    let mut exports: Vec<String> = Vec::new();
    for sym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if sym.st_shndx == 0 {
            imports_fns.push(name.to_string());
        } else if sym.st_bind() == 1 && sym.st_type() != 4 {
            // STB_GLOBAL, not STT_FILE
            exports.push(name.to_string());
        }
    }
    imports_fns.sort();
    imports_fns.dedup();
    exports.sort();
    exports.dedup();

    // ELF has no per-DLL grouping; needed libraries are separate. Present the
    // undefined symbols under a synthetic "dynamic" bucket plus the DT_NEEDED list.
    let imports = if imports_fns.is_empty() {
        Vec::new()
    } else {
        vec![ImportedLib {
            name: "(dynamic symbols)".to_string(),
            functions: imports_fns,
        }]
    };

    // Defined function symbols (STT_FUNC, non-zero address) seed the engine.
    // syms use .strtab, dynsyms use .dynstrtab; keep them separate.
    let mut symbols: Vec<Symbol> = Vec::new();
    let mut collect_funcs = |it: goblin::elf::sym::SymIterator, strtab: &goblin::strtab::Strtab| {
        for sym in it {
            if sym.st_type() != 2 || sym.st_value == 0 || sym.st_shndx == 0 {
                continue; // STT_FUNC, defined, with an address
            }
            let name = strtab.get_at(sym.st_name).unwrap_or("");
            if !name.is_empty() {
                symbols.push(Symbol {
                    addr: sym.st_value,
                    name: name.to_string(),
                    kind: SymKind::Func,
                });
            }
        }
    };
    collect_funcs(elf.syms.iter(), &elf.strtab);
    collect_funcs(elf.dynsyms.iter(), &elf.dynstrtab);

    // Import slots. Every PLT/GOT relocation binds a slot address to a dynamic
    // symbol, and the `.plt` stub that jumps through that slot is what code
    // actually calls. Recording the slot is what later lets a `call` land on
    // `strcpy@plt` instead of an anonymous `sub_`. dynrelas/dynrels are
    // included because a full-RELRO build resolves everything eagerly and has
    // no lazy PLT relocations at all.
    for reloc in elf
        .pltrelocs
        .iter()
        .chain(elf.dynrelas.iter())
        .chain(elf.dynrels.iter())
    {
        if reloc.r_offset == 0 {
            continue;
        }
        let Some(sym) = elf.dynsyms.get(reloc.r_sym) else {
            continue;
        };
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        if !name.is_empty() {
            symbols.push(Symbol {
                addr: reloc.r_offset,
                name: name.to_string(),
                kind: SymKind::Import,
            });
        }
    }

    let stripped = !elf.section_headers.iter().any(|sh| sh.sh_type == 2); // SHT_SYMTAB present == not stripped

    // Mitigation facts. PT_GNU_STACK is tri-state on purpose: present-and-
    // writable-only is the hardened case, present-and-executable is a real
    // finding, and absent is also a finding because the loader then falls back
    // to an executable stack.
    let gnu_stack_exec = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_GNU_STACK)
        .map(|ph| ph.p_flags & PF_X != 0);
    let gnu_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    // Full RELRO needs the GOT resolved eagerly at load; either spelling counts.
    let (dyn_flags, dyn_flags_1) = elf
        .dynamic
        .as_ref()
        .map(|d| (d.info.flags, d.info.flags_1))
        .unwrap_or((0, 0));
    let bind_now = dyn_flags & DF_BIND_NOW != 0
        || dyn_flags_1 & DF_1_NOW != 0
        || elf.dynamic.as_ref().is_some_and(|d| {
            d.dyns
                .iter()
                .any(|e| e.d_tag == goblin::elf::dynamic::DT_BIND_NOW)
        });
    let textrel = elf.dynamic.as_ref().is_some_and(|d| d.info.textrel);

    // A stack cookie shows up as a reference to the guard/fail helpers, and
    // FORTIFY_SOURCE as the `_chk` libc variants. Both are symbol-level facts,
    // so they survive stripping of local symbols.
    let sym_names = || {
        elf.dynsyms
            .iter()
            .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
            .chain(elf.syms.iter().filter_map(|s| elf.strtab.get_at(s.st_name)))
    };
    let stack_chk = sym_names().any(|n| n.starts_with("__stack_chk"));
    let fortify_syms = {
        let mut v: Vec<&str> = sym_names().filter(|n| n.ends_with("_chk")).collect();
        v.sort_unstable();
        v.dedup();
        // `__stack_chk_fail` also ends in `_chk`-adjacent text; count only the
        // fortified wrappers so the number means what it claims.
        v.iter().filter(|n| !n.starts_with("__stack_chk")).count()
    };

    // ET_DYN alone does not mean PIE: shared libraries are ET_DYN too. A PIE
    // executable is the one that also carries an interpreter (or says DF_1_PIE).
    let is_pie_exe = elf.header.e_type == 3
        && (elf.interpreter.is_some() || dyn_flags_1 & DF_1_PIE != 0)
        && elf.entry != 0;

    let mut notes = Vec::new();
    notes.push(format!("ELF{}", if elf.is_64 { "64" } else { "32" }));
    notes.push(if elf.little_endian {
        "LE".into()
    } else {
        "BE".into()
    });
    match elf.header.e_type {
        1 => notes.push("relocatable".into()),
        2 => notes.push("executable".into()),
        // ET_DYN covers both PIE programs and shared libraries; an interpreter
        // is what tells them apart, and the distinction matters enough to a
        // reader that it is worth making here rather than lumping them.
        3 if is_pie_exe => notes.push("PIE executable".into()),
        3 => notes.push("shared object".into()),
        4 => notes.push("core dump".into()),
        _ => {}
    }
    if elf.interpreter.is_some() {
        notes.push("dynamically linked".into());
    } else if elf.header.e_type == 2 {
        notes.push("statically linked".into());
    }

    Binary {
        path: path.to_string(),
        size: bytes.len() as u64,
        format: Format::Elf,
        arch,
        bits: if elf.is_64 { 64 } else { 32 },
        endian_little: elf.little_endian,
        is_lib: elf.header.e_type == 3 && !is_pie_exe,
        is_stripped: stripped,
        entry: elf.entry,
        image_base: 0,
        subsystem: None,
        timestamp: None,
        sections,
        imports,
        exports,
        symbols,
        func_hints: Vec::new(),
        libs: elf.libraries.iter().map(|s| s.to_string()).collect(),
        rpaths: elf
            .rpaths
            .iter()
            .chain(elf.runpaths.iter())
            .map(|s| s.to_string())
            .collect(),
        overall_entropy: 0.0,
        overlay_off: None,
        overlay_size: 0,
        overlay_entropy: 0.0,
        has_signature: false,
        sig_region: None,
        hardening: HardeningFacts {
            gnu_stack_exec,
            gnu_relro,
            bind_now,
            textrel,
            has_interp: elf.interpreter.is_some(),
            elf_type: elf.header.e_type,
            stack_chk,
            fortify_syms,
            ..Default::default()
        },
        notes,
    }
}
