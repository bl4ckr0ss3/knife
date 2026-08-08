//! PE → Binary.

use super::mk_section;
use crate::model::{
    Arch, Binary, Format, HardeningFacts, ImportedLib, LoadConfig, SymKind, Symbol,
};
use goblin::pe::PE;
use std::collections::BTreeMap;

const MEM_EXECUTE: u32 = 0x2000_0000;
const MEM_READ: u32 = 0x4000_0000;
const MEM_WRITE: u32 = 0x8000_0000;

pub fn build(path: &str, bytes: &[u8], pe: PE) -> Binary {
    let arch = match pe.header.coff_header.machine {
        0x014c => Arch::X86,
        0x8664 => Arch::X86_64,
        0x01c0 | 0x01c4 => Arch::Arm,
        0xaa64 => Arch::Aarch64,
        _ => Arch::Other,
    };

    let sections: Vec<crate::model::Section> = pe
        .sections
        .iter()
        .map(|s| {
            let name = s.name().unwrap_or("(bad)").to_string();
            let c = s.characteristics;
            mk_section(
                name,
                s.virtual_address as u64,
                s.virtual_size as u64,
                s.pointer_to_raw_data as u64,
                s.size_of_raw_data as u64,
                c & MEM_READ != 0,
                c & MEM_WRITE != 0,
                c & MEM_EXECUTE != 0,
                bytes,
            )
        })
        .collect();

    // goblin yields one Import per function; group them by DLL.
    let mut by_dll: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for imp in &pe.imports {
        by_dll
            .entry(imp.dll.to_string())
            .or_default()
            .push(imp.name.to_string());
    }
    // preserve the library order from the import table where possible
    let mut imports: Vec<ImportedLib> = Vec::new();
    for lib in &pe.libraries {
        if let Some(fns) = by_dll.remove(*lib) {
            imports.push(ImportedLib {
                name: lib.to_string(),
                functions: fns,
            });
        }
    }
    for (name, functions) in by_dll {
        imports.push(ImportedLib { name, functions });
    }

    let exports = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(|n| n.to_string()))
        .collect();

    // Addressed symbols for the analysis engine: export RVAs, and each import's
    // IAT-slot RVA (so `call [rip+x]` through the IAT can be named).
    let mut symbols: Vec<Symbol> = Vec::new();
    for e in &pe.exports {
        if let (Some(name), rva) = (e.name, e.rva) {
            symbols.push(Symbol {
                addr: rva as u64,
                name: name.to_string(),
                kind: SymKind::Export,
            });
        }
    }
    for imp in &pe.imports {
        let module = imp.dll.rsplit_once('.').map(|(s, _)| s).unwrap_or(imp.dll);
        symbols.push(Symbol {
            // goblin names these two fields the opposite way round from what
            // they hold: `rva` points at the hint/name string, while `offset`
            // is the import address table slot RVA. Code calls through the
            // slot, so the slot is the address worth recording.
            addr: imp.offset as u64,
            name: format!("{module}!{}", imp.name),
            kind: SymKind::Import,
        });
    }

    let (subsystem, image_base, timestamp, has_sig, sig_region) =
        if let Some(oh) = pe.header.optional_header {
            let sub = subsystem_name(oh.windows_fields.subsystem);
            // For the certificate table the "virtual_address" field is really a
            // file offset, not an RVA.
            let cert = oh.data_directories.get_certificate_table();
            let region = cert
                .filter(|d| d.size > 0)
                .map(|d| (d.virtual_address as u64, d.size as u64));
            (
                Some(sub.to_string()),
                oh.windows_fields.image_base,
                Some(pe.header.coff_header.time_date_stamp as i64),
                region.is_some(),
                region,
            )
        } else {
            (None, pe.image_base as u64, None, false, None)
        };

    // Mitigation facts. The DLL characteristics word carries the loader's
    // opt-ins (ASLR, DEP, CFG); the load config directory carries the data that
    // actually backs the stack cookie and CFG, which is the part a linker flag
    // alone does not prove.
    let dll_characteristics = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.dll_characteristics);
    let load_config = pe
        .header
        .optional_header
        .and_then(|oh| oh.data_directories.get_load_config_table().copied())
        .filter(|d| d.virtual_address != 0 && d.size > 0)
        .and_then(|d| {
            let off = rva_to_off(&sections, d.virtual_address as u64)?;
            parse_load_config(bytes, off as usize, pe.is_64)
        });

    // The exception directory lists every non-leaf function on x64 with its
    // start address, so it recovers the code that recursive descent misses when
    // functions are reached only through vtables and function pointers. That is
    // most of a stripped C++ binary, which is why this matters so much more than
    // its size suggests.
    let func_hints = exception_function_starts(&pe, &sections, bytes);

    let mut notes = Vec::new();
    if pe.is_64 {
        notes.push("PE32+".into());
    } else {
        notes.push("PE32".into());
    }
    if !func_hints.is_empty() {
        notes.push(format!("{} pdata functions", func_hints.len()));
    }
    let dotnet = pe
        .header
        .optional_header
        .and_then(|oh| oh.data_directories.get_clr_runtime_header().copied())
        .map(|d| d.virtual_address != 0)
        .unwrap_or(false);
    if dotnet {
        notes.push(".NET / CLR".into());
    }

    Binary {
        path: path.to_string(),
        size: bytes.len() as u64,
        format: Format::Pe,
        arch,
        bits: if pe.is_64 { 64 } else { 32 },
        endian_little: true,
        is_lib: pe.is_lib,
        is_stripped: false,
        entry: pe.entry as u64,
        image_base,
        subsystem,
        timestamp,
        sections,
        imports,
        exports,
        symbols,
        func_hints,
        libs: pe.libraries.iter().map(|s| s.to_string()).collect(),
        rpaths: Vec::new(),
        overall_entropy: 0.0,
        overlay_off: None,
        overlay_size: 0,
        overlay_entropy: 0.0,
        has_signature: has_sig,
        sig_region,
        hardening: HardeningFacts {
            dll_characteristics,
            load_config,
            ..Default::default()
        },
        notes,
    }
}

/// Function-start RVAs from the PE exception directory.
///
/// Each RUNTIME_FUNCTION names a code region and its unwind info. A function
/// with more than one region is split across several entries whose tails are
/// flagged CHAININFO in their unwind info; those tails are continuations, not
/// separate functions, so they are skipped. What remains is one address per
/// real function, which is exactly the seed set the engine cannot derive from
/// control flow alone.
fn exception_function_starts(
    pe: &PE,
    sections: &[crate::model::Section],
    bytes: &[u8],
) -> Vec<u64> {
    const UNW_FLAG_CHAININFO: u8 = 0x4;
    let Some(ed) = &pe.exception_data else {
        return Vec::new();
    };

    let mut starts = Vec::new();
    for rf in ed.functions().flatten() {
        // The unwind info's first byte packs version (low 3 bits) and flags
        // (high 5); a chained entry continues an earlier function.
        let chained = rva_to_off(sections, rf.unwind_info_address as u64)
            .and_then(|o| bytes.get(o as usize).copied())
            .map(|b| (b >> 3) & UNW_FLAG_CHAININFO != 0)
            .unwrap_or(false);
        if !chained {
            starts.push(rf.begin_address as u64);
        }
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

/// RVA → file offset over the section table. Used before the `Binary` exists,
/// so it takes the sections directly.
fn rva_to_off(sections: &[crate::model::Section], rva: u64) -> Option<u64> {
    sections.iter().find_map(|s| {
        let span = s.vsize.max(s.file_size);
        (s.vaddr != 0 && rva >= s.vaddr && rva < s.vaddr + span)
            .then(|| s.file_off + (rva - s.vaddr))
    })
}

/// IMAGE_LOAD_CONFIG_DIRECTORY. The 32- and 64-bit layouts differ in more than
/// pointer width (several scalar fields change size too), so the field offsets
/// are listed per width rather than computed. Every read is bounds-checked
/// against the directory's own `Size`, because a truncated or hand-built
/// directory is exactly the kind of thing worth surviving rather than panicking
/// on.
fn parse_load_config(bytes: &[u8], off: usize, is_64: bool) -> Option<LoadConfig> {
    let d32 = |o: usize| -> u64 {
        bytes
            .get(off + o..off + o + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
            .unwrap_or(0)
    };
    let d64 = |o: usize| -> u64 {
        bytes
            .get(off + o..off + o + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0)
    };

    // The directory's declared size tells us which trailing fields exist at all;
    // CFG fields are absent in binaries built before they were defined.
    let size = d32(0) as usize;
    if size < 0x40 {
        return None;
    }
    // Read a field only when the directory is long enough to contain it, named
    // by where the field *ends* so the bound reads off the layout directly.
    let w64 = |ends: usize, at: usize| if size >= ends { d64(at) } else { 0 };
    let w32 = |ends: usize, at: usize| if size >= ends { d32(at) } else { 0 };

    Some(if is_64 {
        LoadConfig {
            security_cookie: w64(0x60, 0x58),
            seh_table: w64(0x68, 0x60),
            seh_count: w64(0x70, 0x68),
            guard_cf_count: w64(0x90, 0x88),
            guard_flags: w32(0x94, 0x90) as u32,
        }
    } else {
        LoadConfig {
            security_cookie: w32(0x40, 0x3c),
            seh_table: w32(0x44, 0x40),
            seh_count: w32(0x48, 0x44),
            guard_cf_count: w32(0x58, 0x54),
            guard_flags: w32(0x5c, 0x58) as u32,
        }
    })
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "GUI",
        3 => "console",
        9 => "Windows CE",
        10 => "EFI application",
        _ => "unknown",
    }
}
