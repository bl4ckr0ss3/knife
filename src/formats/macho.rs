//! Mach-O → Binary. Fat binaries: the first architecture slice is used.

use super::mk_section;
use crate::model::{Arch, Binary, Format, ImportedLib};
use anyhow::{bail, Result};
use goblin::mach::{Mach, MachO};

const CPU_ARCH_ABI64: u32 = 0x0100_0000;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_ARM: u32 = 12;

const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;

pub fn build(path: &str, bytes: &[u8], mach: Mach) -> Result<Binary> {
    let macho = match mach {
        Mach::Binary(m) => m,
        Mach::Fat(fat) => match fat.into_iter().next() {
            Some(Ok(goblin::mach::SingleArch::MachO(m))) => m,
            _ => bail!("fat Mach-O: no usable architecture slice"),
        },
    };
    Ok(build_one(path, bytes, macho))
}

fn build_one(path: &str, bytes: &[u8], m: MachO) -> Binary {
    let ct = m.header.cputype;
    let is64 = ct & CPU_ARCH_ABI64 != 0;
    let base = ct & !CPU_ARCH_ABI64;
    let arch = match base {
        CPU_TYPE_X86 if is64 => Arch::X86_64,
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_ARM if is64 => Arch::Aarch64,
        CPU_TYPE_ARM => Arch::Arm,
        _ => Arch::Other,
    };

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
        }]
    };
    let exports: Vec<String> = m
        .exports()
        .map(|v| v.into_iter().map(|e| e.name).collect())
        .unwrap_or_default();

    let mut notes = vec!["Mach-O".to_string()];
    notes.push(if is64 {
        "64-bit".into()
    } else {
        "32-bit".into()
    });

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
        libs: m.libs.iter().map(|s| s.to_string()).collect(),
        rpaths: m.rpaths.iter().map(|s| s.to_string()).collect(),
        overall_entropy: 0.0,
        overlay_off: None,
        overlay_size: 0,
        overlay_entropy: 0.0,
        has_signature: false,
        sig_region: None,
        notes,
    }
}
