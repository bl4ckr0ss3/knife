//! ELF → Binary.

use super::mk_section;
use crate::model::{Arch, Binary, Format, ImportedLib};
use goblin::elf::Elf;

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

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

    let stripped = !elf.section_headers.iter().any(|sh| sh.sh_type == 2); // SHT_SYMTAB present == not stripped

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
        3 => notes.push("shared object / PIE".into()),
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
        is_lib: elf.header.e_type == 3,
        is_stripped: stripped,
        entry: elf.entry,
        image_base: 0,
        subsystem: None,
        timestamp: None,
        sections,
        imports,
        exports,
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
        notes,
    }
}
