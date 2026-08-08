//! PE → Binary.

use super::mk_section;
use crate::model::{Arch, Binary, Format, ImportedLib};
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

    let sections = pe
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

    let mut notes = Vec::new();
    if pe.is_64 {
        notes.push("PE32+".into());
    } else {
        notes.push("PE32".into());
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
        libs: pe.libraries.iter().map(|s| s.to_string()).collect(),
        rpaths: Vec::new(),
        overall_entropy: 0.0,
        overlay_off: None,
        overlay_size: 0,
        overlay_entropy: 0.0,
        has_signature: has_sig,
        sig_region,
        notes,
    }
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
