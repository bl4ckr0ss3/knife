//! x86/x64 disassembly via iced-x86. Other architectures are reported as
//! unsupported rather than guessed at.

use crate::model::{Arch, Binary};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

pub struct Insn {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// Map a virtual address (PE RVA / ELF VA) to a file offset via the sections.
pub fn vaddr_to_off(bin: &Binary, vaddr: u64) -> Option<u64> {
    for s in &bin.sections {
        let span = s.vsize.max(s.file_size);
        if s.vaddr != 0 && vaddr >= s.vaddr && vaddr < s.vaddr + span {
            return Some(s.file_off + (vaddr - s.vaddr));
        }
    }
    None
}

/// Resolve where execution starts, as a (file_offset, virtual_address) pair.
pub fn entry_location(bin: &Binary, bytes: &[u8]) -> Option<(u64, u64)> {
    // PE: entry is an RVA, virtual address is image_base + entry.
    // ELF: entry is already a VA.
    let (off, va) = match bin.format {
        crate::model::Format::Pe => (vaddr_to_off(bin, bin.entry)?, bin.image_base + bin.entry),
        crate::model::Format::Elf => (vaddr_to_off(bin, bin.entry)?, bin.entry),
        _ => {
            // Mach-O and friends: try as a vaddr, then fall back to a raw offset.
            if let Some(o) = vaddr_to_off(bin, bin.entry) {
                (o, bin.entry)
            } else if bin.entry < bytes.len() as u64 {
                (bin.entry, bin.entry)
            } else {
                return None;
            }
        }
    };
    if off < bytes.len() as u64 {
        Some((off, va))
    } else {
        None
    }
}

pub fn supported(arch: Arch) -> bool {
    arch.is_x86()
}

/// Disassemble up to `count` instructions from `file_off`, presenting addresses
/// as if the code were loaded at `va`.
pub fn disassemble(bytes: &[u8], file_off: u64, va: u64, bits: u32, count: usize) -> Vec<Insn> {
    let start = file_off as usize;
    if start >= bytes.len() {
        return Vec::new();
    }
    let code = &bytes[start..];
    let mut decoder = Decoder::with_ip(bits, code, va, DecoderOptions::NONE);
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_uppercase_hex(false);
    fmt.options_mut().set_hex_prefix("0x");
    fmt.options_mut().set_hex_suffix("");
    fmt.options_mut().set_space_after_operand_separator(true);

    let mut out = Vec::with_capacity(count);
    let mut insn = Instruction::default();
    let mut text = String::new();
    while out.len() < count && decoder.can_decode() {
        decoder.decode_out(&mut insn);
        text.clear();
        fmt.format(&insn, &mut text);

        let lo = (insn.ip() - va) as usize;
        let hi = lo + insn.len();
        let raw = code.get(lo..hi).unwrap_or(&[]).to_vec();

        out.push(Insn {
            addr: insn.ip(),
            bytes: raw,
            text: text.clone(),
        });
    }
    out
}
