//! Synthetic binaries for tests.
//!
//! The ELF import path has a lot of moving parts (dynamic segment, relocation
//! table, PLT stub, call site) and no amount of unit testing the pieces proves
//! they line up. Rather than depend on a checked-in binary or on whatever
//! happens to be installed on the test machine, we assemble a small but real
//! ELF here: goblin parses it exactly as it parses anything else, so the test
//! exercises the whole chain and runs identically on every platform.

#![cfg(test)]

const EHDR: usize = 64;
const PHDR: usize = 56;
const SHDR: usize = 64;

// Layout. Offsets equal virtual addresses throughout, which keeps the
// address-to-offset mapping an identity and the arithmetic below readable.
const P_DYNSTR: u64 = 0x00e8;
const P_DYNSYM: u64 = 0x00f0;
const P_RELA: u64 = 0x0120;
const P_DYNAMIC: u64 = 0x0138;
const P_PLT: u64 = 0x01c0;
const P_TEXT: u64 = 0x01d0;
const P_GOT: u64 = 0x01e0;
const P_SHSTR: u64 = 0x01e8;
const P_SHDRS: u64 = 0x0208;
const FILE_END: u64 = P_SHDRS + 5 * SHDR as u64;

const DYNSTR: &[u8] = b"\0strcpy\0";
const SHSTR: &[u8] = b"\0.plt\0.text\0.got.plt\0.shstrtab\0";

/// A 64-bit x86 ELF executable that calls `strcpy` through a PLT stub.
///
/// The interesting part is the chain: `.text` calls `.plt`, the stub jumps
/// through a GOT slot, and a `R_X86_64_JUMP_SLOT` relocation binds that slot to
/// the dynamic symbol `strcpy`. Resolving the call name requires every link.
pub fn elf_with_plt_call() -> Vec<u8> {
    let mut f = vec![0u8; FILE_END as usize];

    // ── ELF header ──
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // ELFCLASS64
    f[5] = 1; // ELFDATA2LSB
    f[6] = 1; // EV_CURRENT
    put16(&mut f, 16, 2); // e_type = ET_EXEC
    put16(&mut f, 18, 62); // e_machine = x86-64
    put32(&mut f, 20, 1); // e_version
    put64(&mut f, 24, P_TEXT); // e_entry
    put64(&mut f, 32, EHDR as u64); // e_phoff
    put64(&mut f, 40, P_SHDRS); // e_shoff
    put16(&mut f, 52, EHDR as u16); // e_ehsize
    put16(&mut f, 54, PHDR as u16); // e_phentsize
    put16(&mut f, 56, 3); // e_phnum
    put16(&mut f, 58, SHDR as u16); // e_shentsize
    put16(&mut f, 60, 5); // e_shnum
    put16(&mut f, 62, 4); // e_shstrndx

    // ── program headers ──
    // PT_LOAD covering the file, PT_DYNAMIC so goblin finds the dynamic info,
    // and a non-executable PT_GNU_STACK so the hardening audit sees NX on.
    let ph = EHDR;
    phdr(&mut f, ph, 1, 7, 0, 0, FILE_END, 0x1000); // PT_LOAD, RWX
    phdr(&mut f, ph + PHDR, 2, 6, P_DYNAMIC, P_DYNAMIC, 128, 8); // PT_DYNAMIC, RW
    phdr(&mut f, ph + 2 * PHDR, 0x6474_e551, 6, 0, 0, 0, 16); // PT_GNU_STACK, RW

    // ── .dynstr / .dynsym ──
    let o = P_DYNSTR as usize;
    f[o..o + DYNSTR.len()].copy_from_slice(DYNSTR);

    // dynsym[0] is the reserved null entry; dynsym[1] is undefined `strcpy`.
    let s = P_DYNSYM as usize + 24;
    put32(&mut f, s, 1); // st_name -> "strcpy"
    f[s + 4] = 0x12; // STB_GLOBAL | STT_FUNC
    put16(&mut f, s + 6, 0); // st_shndx = SHN_UNDEF

    // ── .rela.plt: bind the GOT slot to dynsym[1] ──
    let r = P_RELA as usize;
    put64(&mut f, r, P_GOT); // r_offset
    put64(&mut f, r + 8, (1u64 << 32) | 7); // r_info: sym 1, R_X86_64_JUMP_SLOT

    // ── .dynamic ──
    let dyn_entries: [(u64, u64); 8] = [
        (5, P_DYNSTR), // DT_STRTAB
        (10, 8),       // DT_STRSZ
        (6, P_DYNSYM), // DT_SYMTAB
        (11, 24),      // DT_SYMENT
        (23, P_RELA),  // DT_JMPREL
        (2, 24),       // DT_PLTRELSZ
        (20, 7),       // DT_PLTREL = DT_RELA
        (0, 0),        // DT_NULL
    ];
    for (i, (tag, val)) in dyn_entries.iter().enumerate() {
        let d = P_DYNAMIC as usize + i * 16;
        put64(&mut f, d, *tag);
        put64(&mut f, d + 8, *val);
    }

    // ── .plt: jmp qword ptr [rip + disp] -> GOT slot ──
    // The displacement is relative to the end of the instruction, six bytes in.
    let p = P_PLT as usize;
    f[p] = 0xff;
    f[p + 1] = 0x25;
    let disp = (P_GOT as i64 - (P_PLT as i64 + 6)) as i32;
    f[p + 2..p + 6].copy_from_slice(&disp.to_le_bytes());

    // ── .text: call the stub, then return ──
    let t = P_TEXT as usize;
    f[t] = 0xe8;
    let rel = (P_PLT as i64 - (P_TEXT as i64 + 5)) as i32;
    f[t + 1..t + 5].copy_from_slice(&rel.to_le_bytes());
    f[t + 5] = 0xc3;

    // ── .shstrtab ──
    let sh = P_SHSTR as usize;
    f[sh..sh + SHSTR.len()].copy_from_slice(SHSTR);

    // ── section headers ──
    const PROGBITS: u32 = 1;
    const STRTAB: u32 = 3;
    const ALLOC_EXEC: u64 = 0x2 | 0x4;
    const ALLOC_WRITE: u64 = 0x2 | 0x1;
    let sd = P_SHDRS as usize;
    shdr(&mut f, sd + SHDR, 1, PROGBITS, ALLOC_EXEC, P_PLT, 16); // .plt
    shdr(&mut f, sd + 2 * SHDR, 6, PROGBITS, ALLOC_EXEC, P_TEXT, 16); // .text
    shdr(&mut f, sd + 3 * SHDR, 12, PROGBITS, ALLOC_WRITE, P_GOT, 8); // .got.plt
    shdr(&mut f, sd + 4 * SHDR, 21, STRTAB, 0, 0, SHSTR.len() as u64); // .shstrtab
                                                                       // .shstrtab is not mapped, so its offset must be set explicitly.
    put64(&mut f, sd + 4 * SHDR + 24, P_SHSTR);

    f
}

fn put16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(f: &mut [u8], at: usize, v: u64) {
    f[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

// The argument list mirrors the on-disk header layout, which reads more
// clearly here than a struct that exists only to be immediately destructured.
#[allow(clippy::too_many_arguments)]
fn phdr(f: &mut [u8], at: usize, ty: u32, flags: u32, off: u64, va: u64, sz: u64, align: u64) {
    put32(f, at, ty);
    put32(f, at + 4, flags);
    put64(f, at + 8, off);
    put64(f, at + 16, va);
    put64(f, at + 24, va); // p_paddr
    put64(f, at + 32, sz); // p_filesz
    put64(f, at + 40, sz); // p_memsz
    put64(f, at + 48, align);
}

/// Mapped sections only, where the file offset equals the virtual address.
fn shdr(f: &mut [u8], at: usize, name: u32, ty: u32, flags: u64, addr: u64, size: u64) {
    put32(f, at, name);
    put32(f, at + 4, ty);
    put64(f, at + 8, flags);
    put64(f, at + 16, addr);
    put64(f, at + 24, addr); // sh_offset == sh_addr by construction
    put64(f, at + 32, size);
    put64(f, at + 48, 1); // sh_addralign
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Format, SymKind};

    #[test]
    fn the_fixture_parses_as_an_elf() {
        let bytes = elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).expect("parses");
        assert_eq!(bin.format, Format::Elf);
        assert_eq!(bin.bits, 64);
        assert_eq!(bin.entry, P_TEXT);
        assert!(bin.sections.iter().any(|s| s.name == ".plt" && s.exec));
    }

    #[test]
    fn the_relocation_names_the_got_slot() {
        let bytes = elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        let slot = bin
            .symbols
            .iter()
            .find(|s| s.kind == SymKind::Import)
            .expect("an import symbol from .rela.plt");
        assert_eq!(slot.addr, P_GOT);
        assert_eq!(slot.name, "strcpy");
    }
}
