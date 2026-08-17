//! Synthetic binaries for tests.
//!
//! The per-format import paths have a lot of moving parts (dynamic segment and
//! relocation table for ELF, import descriptors and IAT for PE, dyld bind
//! opcodes for Mach-O) and no amount of unit testing the pieces proves they
//! line up. Rather than depend on checked-in binaries or on whatever happens
//! to be installed on the test machine, we assemble small but real binaries of
//! all three formats here: goblin parses them exactly as it parses anything
//! else, so the tests exercise the whole chain and run identically on every
//! platform.

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

/// `bl` from `pc` to `target` (A64, direct branch). The branch offset is
/// measured from the instruction itself: `target = pc + imm26*4`.
fn bl_word(pc: u64, target: u64) -> u32 {
    let off = target.wrapping_sub(pc);
    0x9400_0000 | ((off >> 2) as u32 & 0x03ff_ffff)
}

// ────────────────────────────────────────────────────────────────────────────
// AArch64
//
// Same identity-mapped ELF trick as `elf_with_plt_call`. One variant exercises
// the plain engine path (internal call), the other carries the full dynamic
// plumbing so the GOT veneer (`adrp`/`ldr`/`br`) can be resolved to `strcpy`.
// ────────────────────────────────────────────────────────────────────────────

/// A 64-bit AArch64 ELF: entry at `P_TEXT` calls an internal helper at
/// `P_TEXT+0x10` and returns; the helper is two instructions and a ret.
pub fn elf_aarch64_call() -> Vec<u8> {
    let text_len = 0x1cusize;
    let shstr = b"\0.text\0.shstrtab\0";
    const SHDRS: u64 = 0x0208;
    const SHSTR_OFF: u64 = 0x01f0;
    let file_end = SHDRS + 3 * SHDR as u64;

    let mut f = vec![0u8; file_end as usize];

    // ── ELF header ──
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // ELFCLASS64
    f[5] = 1; // ELFDATA2LSB
    f[6] = 1; // EV_CURRENT
    put16(&mut f, 16, 2); // e_type = ET_EXEC
    put16(&mut f, 18, 183); // e_machine = AArch64
    put32(&mut f, 20, 1); // e_version
    put64(&mut f, 24, P_TEXT); // e_entry
    put64(&mut f, 32, EHDR as u64); // e_phoff
    put64(&mut f, 40, SHDRS); // e_shoff
    put16(&mut f, 52, EHDR as u16); // e_ehsize
    put16(&mut f, 54, PHDR as u16); // e_phentsize
    put16(&mut f, 56, 2); // e_phnum
    put16(&mut f, 58, SHDR as u16); // e_shentsize
    put16(&mut f, 60, 3); // e_shnum
    put16(&mut f, 62, 2); // e_shstrndx

    // ── program headers: one RWX load, one NX stack ──
    phdr(&mut f, EHDR, 1, 7, 0, 0, file_end, 0x1000); // PT_LOAD, RWX
    phdr(&mut f, EHDR + PHDR, 0x6474_e551, 6, 0, 0, 0, 16); // PT_GNU_STACK

    // ── .text ──
    // entry:   bl helper (P_TEXT + 0x10)
    //          movz x0, #0x2a
    //          ret
    //          nop
    // helper:  add x0, x1, x2
    //          ldr x1, [x0, #0]
    //          ret
    let t = P_TEXT as usize;
    put32(&mut f, t, bl_word(P_TEXT, P_TEXT + 0x10));
    put32(&mut f, t + 4, 0xd280_0540); // movz x0, #0x2a
    put32(&mut f, t + 8, 0xd65f_03c0); // ret
    put32(&mut f, t + 12, 0xd503_201f); // nop
    put32(&mut f, t + 16, 0x8b02_0020); // add x0, x1, x2
    put32(&mut f, t + 20, 0xf940_0001); // ldr x1, [x0, #0]
    put32(&mut f, t + 24, 0xd65f_03c0); // ret

    // ── .shstrtab ──
    let s = SHSTR_OFF as usize;
    f[s..s + shstr.len()].copy_from_slice(shstr);

    // ── section headers ──
    const PROGBITS: u32 = 1;
    const STRTAB: u32 = 3;
    const ALLOC_EXEC: u64 = 0x2 | 0x4;
    let sd = SHDRS as usize;
    shdr(
        &mut f,
        sd + SHDR,
        1,
        PROGBITS,
        ALLOC_EXEC,
        P_TEXT,
        text_len as u64,
    ); // .text
    shdr(&mut f, sd + 2 * SHDR, 7, STRTAB, 0, 0, shstr.len() as u64); // .shstrtab
    put64(&mut f, sd + 2 * SHDR + 24, SHSTR_OFF); // shstrtab is not mapped

    f
}

/// A 64-bit AArch64 ELF that calls `strcpy` through a GOT veneer.
///
/// The interesting part is the chain, mirrored one-for-one from
/// `elf_with_plt_call`: `.text` calls the veneer in `.plt`, the veneer loads
/// the GOT slot via `adrp x17, page; ldr x16, [x17, #lo]; br x16`, and an
/// `R_AARCH64_JUMP_SLOT` relocation binds that slot to `strcpy`. Naming the
/// call therefore requires the whole link, exactly like the x86 sibling.
pub fn elf_aarch64_plt_call() -> Vec<u8> {
    let mut f = vec![0u8; FILE_END as usize];

    // ── ELF header ──
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // ELFCLASS64
    f[5] = 1; // ELFDATA2LSB
    f[6] = 1; // EV_CURRENT
    put16(&mut f, 16, 2); // e_type = ET_EXEC
    put16(&mut f, 18, 183); // e_machine = AArch64
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
    let ph = EHDR;
    phdr(&mut f, ph, 1, 7, 0, 0, FILE_END, 0x1000); // PT_LOAD, RWX
    phdr(&mut f, ph + PHDR, 2, 6, P_DYNAMIC, P_DYNAMIC, 128, 8); // PT_DYNAMIC, RW
    phdr(&mut f, ph + 2 * PHDR, 0x6474_e551, 6, 0, 0, 0, 16); // PT_GNU_STACK, RW

    // ── .dynstr / .dynsym ──
    let o = P_DYNSTR as usize;
    f[o..o + DYNSTR.len()].copy_from_slice(DYNSTR);
    let s = P_DYNSYM as usize + 24;
    put32(&mut f, s, 1); // st_name -> "strcpy"
    f[s + 4] = 0x12; // STB_GLOBAL | STT_FUNC
    put16(&mut f, s + 6, 0); // st_shndx = SHN_UNDEF

    // ── .rela.plt: bind the GOT slot to dynsym[1] ──
    let r = P_RELA as usize;
    put64(&mut f, r, P_GOT); // r_offset
    put64(&mut f, r + 8, (1u64 << 32) | 1026); // sym 1, R_AARCH64_JUMP_SLOT

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

    // ── .plt: the GOT veneer, x17/x16 spelling ──
    let p = P_PLT as usize;
    put32(&mut f, p, adrp_word(P_PLT, P_GOT & !0xfff, 17));
    put32(&mut f, p + 4, ldr_imm_word(17, 16, P_GOT & 0xfff));
    put32(&mut f, p + 8, br_word(16));

    // ── .text: call the veneer, then return ──
    let t = P_TEXT as usize;
    put32(&mut f, t, bl_word(P_TEXT, P_PLT));
    put32(&mut f, t + 4, 0xd65f_03c0); // ret

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
    put64(&mut f, sd + 4 * SHDR + 24, P_SHSTR); // .shstrtab is not mapped

    f
}

/// `adrp rd, page` at `pc` targeting a 4K `page`. Hardware computes the result
/// from `Align(pc, 4096)`, so the immediate is measured from the pc's page.
fn adrp_word(pc: u64, page: u64, rd: u32) -> u32 {
    let off = (page as i64 - (pc & !0xfff) as i64) >> 12;
    let immlo = (off & 3) as u32;
    let immhi = ((off >> 2) & 0x7ffff) as u32;
    0x9000_0000 | (immhi << 5) | (immlo << 29) | rd
}

/// `ldr xt, [xn, #offs]` with a byte-scaled immediate.
fn ldr_imm_word(rn: u32, rt: u32, offs: u64) -> u32 {
    0xf940_0000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | (((offs >> 3) as u32 & 0xfff) << 10)
}

/// `br xn`.
fn br_word(rn: u32) -> u32 {
    0xd61f_0000 | ((rn & 0x1f) << 5)
}

/// A 64-bit ELF carrying a `.eh_frame_hdr` search table that lists two function
/// starts (0x1000 and 0x1400). The table encoding is the near-universal
/// `datarel | sdata4`, so `eh_frame_hdr_starts` recovers both addresses. There
/// is one `PT_GNU_EH_FRAME` program header and nothing else, which is all the
/// discovery path reads.
pub fn elf_with_eh_frame_hdr() -> Vec<u8> {
    const HDR_OFF: u64 = 0x0080; // both file offset and vaddr of .eh_frame_hdr
    let starts = [0x1000u64, 0x1400u64];

    let mut f = vec![0u8; 0x100];

    // ── ELF header ──
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // ELFCLASS64
    f[5] = 1; // ELFDATA2LSB
    f[6] = 1; // EV_CURRENT
    put16(&mut f, 16, 3); // e_type = ET_DYN
    put16(&mut f, 18, 62); // e_machine = x86-64
    put32(&mut f, 20, 1); // e_version
    put64(&mut f, 32, EHDR as u64); // e_phoff
    put16(&mut f, 52, EHDR as u16); // e_ehsize
    put16(&mut f, 54, PHDR as u16); // e_phentsize
    put16(&mut f, 56, 1); // e_phnum

    // ── one program header: PT_GNU_EH_FRAME ──
    phdr(&mut f, EHDR, 0x6474_e550, 4, HDR_OFF, HDR_OFF, 0x40, 4);

    // ── .eh_frame_hdr ──
    let h = HDR_OFF as usize;
    f[h] = 1; // version
    f[h + 1] = 0x1b; // eh_frame_ptr_enc = pcrel sdata4 (4 bytes, skipped)
    f[h + 2] = 0x03; // fde_count_enc = udata4
    f[h + 3] = 0x3b; // table_enc = datarel sdata4
    put32(&mut f, h + 4, 0); // eh_frame_ptr (skipped)
    put32(&mut f, h + 8, starts.len() as u32); // fde_count
                                               // Each row: (initial_location, fde_addr), both sdata4 relative to HDR_OFF.
    let mut row = h + 12;
    for &s in &starts {
        let delta = (s as i64 - HDR_OFF as i64) as i32;
        put32(&mut f, row, delta as u32); // initial_location
        put32(&mut f, row + 4, delta as u32); // fde_addr (value irrelevant here)
        row += 8;
    }

    f
}

// ────────────────────────────────────────────────────────────────────────────
// PE
//
// Identity mapping again: image_base is 0 and each RVA equals its file offset,
// so virtual addresses equal file offsets and the same field names the slot
// the disassembler jumps through and the byte the imports land on.
// ────────────────────────────────────────────────────────────────────────────

// Header chain. Everything between here and the section table is the standard
// PE32+ scaffolding sizes.
pub const PE_SIG: usize = 0x80;
pub const COFF: usize = PE_SIG + 0x04;
pub const OPT: usize = COFF + 0x14;
pub const DATA_DIRS: usize = OPT + 0x70;
pub const SECTION_TABLE: usize = DATA_DIRS + 16 * 8;

pub const PE_TEXT: u64 = 0x1000;
pub const PE_IDATA: u64 = 0x2000;
pub const PE_IMPORT_DIR: u64 = 0x2000;
pub const PE_INT: u64 = 0x2100;
pub const PE_IAT: u64 = 0x2210;
pub const PE_DLL_NAME: u64 = 0x2200;
pub const PE_HINT_NAME: u64 = 0x2300;
pub const PE_LOAD_CONFIG: u64 = 0x2400;
const PE_FILE_END: usize = 0x2500;

/// A 64-bit x86 PE that calls `kernel32!MessageBoxA` through its IAT.
///
/// The chain: `.text` does `call qword ptr [rip+disp]`, the displacement lands
/// in the IAT slot recorded by the import descriptor's FirstThunk, and the
/// descriptor's INT names the slot. .text also carries a real load-config
/// directory so the mitigation parser has something to chew on.
pub fn pe_with_iat_call() -> Vec<u8> {
    let mut f = vec![0u8; PE_FILE_END];

    // ── DOS header: "MZ" and e_lfanew ──
    f[0..2].copy_from_slice(b"MZ");
    put32(&mut f, 0x3c, PE_SIG as u32);

    // ── PE signature + COFF header ──
    f[PE_SIG..PE_SIG + 4].copy_from_slice(b"PE\0\0");
    put16(&mut f, COFF, 0x8664); // machine = x86-64
    put16(&mut f, COFF + 0x02, 2); // number of sections (.text, .idata)
    put32(&mut f, COFF + 0x04, 1); // time date stamp
    put16(&mut f, COFF + 0x10, 0xF0); // size of optional header
    put16(&mut f, COFF + 0x12, 0x22); // EXECUTABLE | LARGE_ADDRESS_AWARE

    // ── PE32+ optional header (offsets from the optional header start) ──
    put16(&mut f, OPT, 0x20b); // magic
    put32(&mut f, OPT + 0x04, 0x100); // size of code
    put32(&mut f, OPT + 0x08, 0x500); // size of initialized data
    put32(&mut f, OPT + 0x10, PE_TEXT as u32); // entry point RVA
    put32(&mut f, OPT + 0x14, PE_TEXT as u32); // base of code
    put64(&mut f, OPT + 0x18, 0); // image base (identity mapping: RVA == offset)
    put32(&mut f, OPT + 0x20, 0x1000); // section alignment
    put32(&mut f, OPT + 0x24, 0x200); // file alignment
    put16(&mut f, OPT + 0x28, 6); // major OS version
    put16(&mut f, OPT + 0x30, 6); // major subsystem version
    put32(&mut f, OPT + 0x38, 0x3000); // size of image
    put32(&mut f, OPT + 0x3c, 0x200); // size of headers
    put16(&mut f, OPT + 0x44, 3); // subsystem = console
    put16(&mut f, OPT + 0x46, 0x40); // DLL characteristics: DYNAMIC_BASE
    put64(&mut f, OPT + 0x48, 0x10_0000); // size of stack reserve
    put64(&mut f, OPT + 0x50, 0x1000); // size of stack commit
    put64(&mut f, OPT + 0x58, 0x10_0000); // size of heap reserve
    put64(&mut f, OPT + 0x60, 0x1000); // size of heap commit
    put32(&mut f, OPT + 0x6c, 16); // number of RVA and sizes
                                   // data directories follow at OPT + 0x70
    let dir = |i: usize| OPT + 0x70 + i * 8;
    put32(&mut f, dir(1), PE_IMPORT_DIR as u32); // import table
    put32(&mut f, dir(1) + 4, 0x30);
    put32(&mut f, dir(10), PE_LOAD_CONFIG as u32); // load config
    put32(&mut f, dir(10) + 4, 0x40);
    put32(&mut f, dir(12), PE_IAT as u32); // import address table
    put32(&mut f, dir(12) + 4, 0x10);

    // ── section headers ──
    const SECTION: u32 = 0x6000_0020; // initialized code | read | exec
    let sh = |i: usize| SECTION_TABLE + i * 40;
    f[sh(0)..sh(0) + 8].copy_from_slice(b".text\x00\x00\x00");
    put32(&mut f, sh(0) + 0x08, 0x200); // virtual size
    put32(&mut f, sh(0) + 0x0c, PE_TEXT as u32); // virtual address
    put32(&mut f, sh(0) + 0x10, 0x200); // size of raw data
    put32(&mut f, sh(0) + 0x14, PE_TEXT as u32); // pointer to raw data
    put32(&mut f, sh(0) + 0x24, SECTION); // characteristics
    f[sh(1)..sh(1) + 8].copy_from_slice(b".idata\x00\x00");
    put32(&mut f, sh(1) + 0x08, 0x500);
    put32(&mut f, sh(1) + 0x0c, PE_IDATA as u32);
    put32(&mut f, sh(1) + 0x10, 0x500);
    put32(&mut f, sh(1) + 0x14, PE_IDATA as u32);
    put32(&mut f, sh(1) + 0x24, 0xC000_0040); // initialized data | read | write

    // ── .idata: one DLL, two named functions ──
    let desc = PE_IMPORT_DIR as usize;
    put32(&mut f, desc, PE_INT as u32); // OriginalFirstThunk
    put32(&mut f, desc + 0x0c, PE_DLL_NAME as u32); // Name
    put32(&mut f, desc + 0x10, PE_IAT as u32); // FirstThunk
                                               // entry 1: all zeros terminates the table (already zeroed)

    // Import Name Table: two hint/name pointers then the terminator.
    put32(&mut f, PE_INT as usize, PE_HINT_NAME as u32);
    put32(&mut f, PE_INT as usize + 8, PE_HINT_NAME as u32 + 0x20);

    // DLL name and hint/name structures.
    f[PE_DLL_NAME as usize..PE_DLL_NAME as usize + 13].copy_from_slice(b"kernel32.dll\0");
    put16(&mut f, PE_HINT_NAME as usize, 1);
    f[PE_HINT_NAME as usize + 2..PE_HINT_NAME as usize + 14].copy_from_slice(b"ExitProcess\0");
    put16(&mut f, PE_HINT_NAME as usize + 0x20, 2);
    f[PE_HINT_NAME as usize + 0x22..PE_HINT_NAME as usize + 0x2e].copy_from_slice(b"MessageBoxA\0");

    // Load config directory: declared size 0x40 with a security cookie, so
    // the mitigation parser reads the 64-bit layout.
    put32(&mut f, PE_LOAD_CONFIG as usize, 0x60); // size
    put64(
        &mut f,
        PE_LOAD_CONFIG as usize + 0x58,
        0xdead_beef_cafe_f00d,
    ); // SecurityCookie

    // ── .text: engine-visible code ──
    let t = PE_TEXT as usize;
    f[t..t + 4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]); // sub rsp, 0x28
                                                            // call qword ptr [rip+disp] -> IAT slot 0x2210
    f[t + 4] = 0xff;
    f[t + 5] = 0x15;
    let disp = (PE_IAT as i64 - (PE_TEXT as i64 + 0x0a)) as i32;
    f[t + 6..t + 0x0a].copy_from_slice(&disp.to_le_bytes());
    f[t + 0x0a..t + 0x0e].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28]); // add rsp, 0x28
    f[t + 0x0e] = 0xc3; // ret

    f
}

// ────────────────────────────────────────────────────────────────────────────
// Mach-O
// ────────────────────────────────────────────────────────────────────────────

/// A 64-bit x86_64 native-subsystem kernel driver with a realistic BYOVD
/// shape: `DriverEntry` at the entry point, ntoskrnl imports (device-creation,
/// symbolic-link, IRP-stack, MmMapIoSpace, RtlCopyMemory) mixed with one
/// ordinal import, a `.pdata` exception directory seeding two functions, a
/// stored `MajorFunction[14]` dispatch hook, an IOCTL constant compare, and a
/// physical-memory map call in the dispatch handler. This is what the driver
/// pass (`knife drv`) and the kernel sinks work against.
///
/// Identity mapping again: image_base is 0 and RVA equals file offset, so the
/// displacement arithmetic below is the same trick the other PE fixture uses.
pub fn pe_with_driver() -> Vec<u8> {
    let mut f = vec![0u8; 0x6800];

    // ── DOS + COFF + optional header (offsets follow the standard PE32+ layout) ──
    f[0..2].copy_from_slice(b"MZ");
    put32(&mut f, 0x3c, 0x80);
    f[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut f, 0x84, 0x8664); // machine = x86-64
    put16(&mut f, 0x86, 4); // number of sections
    put32(&mut f, 0x88, 1); // time date stamp
    put16(&mut f, 0x94, 0xf0); // size of optional header
    put16(&mut f, 0x96, 0x22); // EXECUTABLE | LARGE_ADDRESS_AWARE
    put16(&mut f, 0x98, 0x20b); // optional header magic (PE32+)
    put32(&mut f, 0x9c, 0x200); // size of code
    put32(&mut f, 0xa0, 0x400); // size of initialized data
    put32(&mut f, 0xa8, 0x1000); // entry point = DriverEntry
    put32(&mut f, 0xac, 0x1000); // base of code
    put64(&mut f, 0xb0, 0); // image base
    put32(&mut f, 0xb8, 0x1000); // section alignment
    put32(&mut f, 0xbc, 0x200); // file alignment
    put16(&mut f, 0xc0, 6); // major OS version
    put16(&mut f, 0xc8, 6); // major subsystem version
    put32(&mut f, 0xd0, 0x6800); // size of image
    put32(&mut f, 0xd4, 0x200); // size of headers
    put16(&mut f, 0xdc, 1); // subsystem = native
    put16(&mut f, 0xde, 0x40); // DLL characteristics: DYNAMIC_BASE
    put64(&mut f, 0xe0, 0x10_0000); // size of stack reserve
    put64(&mut f, 0xe8, 0x1000); // size of stack commit
    put64(&mut f, 0xf0, 0x10_0000); // size of heap reserve
    put64(&mut f, 0xf8, 0x1000); // size of heap commit
    put32(&mut f, 0x104, 16); // number of RVA and sizes
    let dir = |i: usize| 0x108 + i * 8;
    put32(&mut f, dir(1), 0x3000); // import table (RVA, size)
    put32(&mut f, dir(1) + 4, 0x28);
    put32(&mut f, dir(3), 0x2800); // exception directory (.pdata)
    put32(&mut f, dir(3) + 4, 0x24);
    put32(&mut f, dir(12), 0x3300); // import address table
    put32(&mut f, dir(12) + 4, 0x40);

    // ── section headers ──
    const SEC_RX: u32 = 0x6000_0020; // code | read | exec
    const SEC_R: u32 = 0x4000_0040; // initialized data | read
    const SEC_RW: u32 = 0xC000_0040; // initialized data | read | write
    let sh = |i: usize| 0x188 + i * 40;
    f[sh(0)..sh(0) + 8].copy_from_slice(b".text\x00\x00\x00");
    put32(&mut f, sh(0) + 0x08, 0x240); // virtual size
    put32(&mut f, sh(0) + 0x0c, 0x1000); // virtual address
    put32(&mut f, sh(0) + 0x10, 0x240); // size of raw data
    put32(&mut f, sh(0) + 0x14, 0x1000); // pointer to raw data
    put32(&mut f, sh(0) + 0x24, SEC_RX);
    f[sh(1)..sh(1) + 8].copy_from_slice(b".rdata\x00\x00");
    put32(&mut f, sh(1) + 0x08, 0x400);
    put32(&mut f, sh(1) + 0x0c, 0x2000);
    put32(&mut f, sh(1) + 0x10, 0x400);
    put32(&mut f, sh(1) + 0x14, 0x2000);
    put32(&mut f, sh(1) + 0x24, SEC_R);
    f[sh(2)..sh(2) + 8].copy_from_slice(b".pdata\x00\x00");
    put32(&mut f, sh(2) + 0x08, 0x30);
    put32(&mut f, sh(2) + 0x0c, 0x2800);
    put32(&mut f, sh(2) + 0x10, 0x30);
    put32(&mut f, sh(2) + 0x14, 0x2800);
    put32(&mut f, sh(2) + 0x24, SEC_R);
    f[sh(3)..sh(3) + 8].copy_from_slice(b".idata\x00\x00");
    put32(&mut f, sh(3) + 0x08, 0x600);
    put32(&mut f, sh(3) + 0x0c, 0x3000);
    put32(&mut f, sh(3) + 0x10, 0x600);
    put32(&mut f, sh(3) + 0x14, 0x3000);
    put32(&mut f, sh(3) + 0x24, SEC_RW);

    // ── .rdata: UNICODE_STRINGs + device names ──
    // \Device\Knifelab: struct at 0x2000, string at 0x2010.
    put16(&mut f, 0x2000, 0x12);
    put16(&mut f, 0x2000 + 2, 0x12);
    put64(&mut f, 0x2000 + 8, 0x2010);
    f[0x2010..0x2010 + b"\\Device\\Knifelab\0".len()].copy_from_slice(b"\\Device\\Knifelab\0");
    // \DosDevices\Knifelab: struct at 0x2080, string at 0x2090.
    put16(&mut f, 0x2080, 0x16);
    put16(&mut f, 0x2080 + 2, 0x16);
    put64(&mut f, 0x2080 + 8, 0x2090);
    f[0x2090..0x2090 + b"\\DosDevices\\Knifelab\0".len()]
        .copy_from_slice(b"\\DosDevices\\Knifelab\0");

    // ── .pdata: DriverEntry (0x1000), DispatchDeviceControl (0x1100),
    //          and an unreferenced helper (0x1200) ──
    put32(&mut f, 0x2800, 0x1000);
    put32(&mut f, 0x2800 + 4, 0x1050);
    put32(&mut f, 0x2800 + 8, 0);
    put32(&mut f, 0x2800 + 12, 0x1100);
    put32(&mut f, 0x2800 + 16, 0x1150);
    put32(&mut f, 0x2800 + 20, 0);
    put32(&mut f, 0x2800 + 24, 0x1200);
    put32(&mut f, 0x2800 + 28, 0x1220);
    put32(&mut f, 0x2800 + 32, 0);

    // ── .idata: ntoskrnl, five by-name + one ordinal ──
    let desc = 0x3000;
    put32(&mut f, desc, 0x3100); // OriginalFirstThunk
    put32(&mut f, desc + 0x10, 0x3300); // FirstThunk
    put32(&mut f, desc + 0x0c, 0x3200); // Name
                                        // INT: five hint/name pointers, one ordinal (KeInitializeMutex = 1310), terminator.
    put32(&mut f, 0x3100, 0x3400);
    put32(&mut f, 0x3100 + 8, 0x3420);
    put32(&mut f, 0x3100 + 16, 0x3430);
    put32(&mut f, 0x3100 + 24, 0x3440);
    put32(&mut f, 0x3100 + 32, 0x3450);
    put64(&mut f, 0x3100 + 40, 0x8000_0000_0000_0000 | 1310);
    // IAT: same slots, in the order code calls them.
    put32(&mut f, 0x3300, 0x3400); // IoCreateDevice
    put32(&mut f, 0x3308, 0x3420); // IoCreateSymbolicLink
    put32(&mut f, 0x3310, 0x3430); // IoGetCurrentIrpStackLocation
    put32(&mut f, 0x3318, 0x3440); // MmMapIoSpace
    put32(&mut f, 0x3320, 0x3450); // RtlCopyMemory
    f[0x3200..0x3200 + b"ntoskrnl.dll\0".len()].copy_from_slice(b"ntoskrnl.dll\0");
    // hint/name blobs
    f[0x3400..0x3400 + b"\0\0IoCreateDevice\0".len()].copy_from_slice(b"\0\0IoCreateDevice\0");
    f[0x3420..0x3420 + b"\0\0IoCreateSymbolicLink\0".len()]
        .copy_from_slice(b"\0\0IoCreateSymbolicLink\0");
    f[0x3430..0x3430 + b"\0\0IoGetCurrentIrpStackLocation\0".len()]
        .copy_from_slice(b"\0\0IoGetCurrentIrpStackLocation\0");
    f[0x3440..0x3440 + b"\0\0MmMapIoSpace\0".len()].copy_from_slice(b"\0\0MmMapIoSpace\0");
    f[0x3450..0x3450 + b"\0\0RtlCopyMemory\0".len()].copy_from_slice(b"\0\0RtlCopyMemory\0");

    // ── .text: DriverEntry @0x1000 ──
    let e = 0x1000usize;
    f[e] = 0x53; // push rbx
    f[e + 1..e + 5].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]); // sub rsp, 0x28
    f[e + 5..e + 8].copy_from_slice(&[0x48, 0x89, 0xcb]); // mov rbx, rcx  (DriverObject)
    f[e + 8..e + 11].copy_from_slice(&[0x48, 0x8d, 0x0d]); // lea rcx,[rip+..] -> 0x2000 (device name)
    put32(&mut f, e + 11, (0x2000u64 - (e as u64 + 15)) as u32);
    f[e + 15..e + 17].copy_from_slice(&[0x33, 0xd2]); // xor edx, edx
    f[e + 17..e + 23].copy_from_slice(&[0x41, 0xb8, 0x22, 0, 0, 0]); // mov r8d, 0x22
    f[e + 23..e + 26].copy_from_slice(&[0x4c, 0x8d, 0x0d]); // lea r9,[rip+..] -> 0x2020 (device object out)
    put32(&mut f, e + 26, (0x2020u64 - (e as u64 + 30)) as u32);
    f[e + 30..e + 32].copy_from_slice(&[0xff, 0x15]); // call [rip+..] -> IoCreateDevice
    put32(&mut f, e + 32, (0x3300u64 - (e as u64 + 36)) as u32);
    // lea rax,[rip+..] -> 0x1100; mov [rbx+0xe0], rax  (MajorFunction[14] = DispatchDeviceControl)
    f[e + 36..e + 39].copy_from_slice(&[0x48, 0x8d, 0x05]);
    put32(&mut f, e + 39, (0x1100u64 - (e as u64 + 43)) as u32);
    f[e + 43..e + 50].copy_from_slice(&[0x48, 0x89, 0x83, 0xe0, 0, 0, 0]);
    // lea rcx,[rip+..] -> 0x2080; call IoCreateSymbolicLink
    f[e + 50..e + 53].copy_from_slice(&[0x48, 0x8d, 0x0d]);
    put32(&mut f, e + 53, (0x2080u64 - (e as u64 + 57)) as u32);
    f[e + 57..e + 59].copy_from_slice(&[0xff, 0x15]);
    put32(&mut f, e + 59, (0x3308u64 - (e as u64 + 63)) as u32);
    f[e + 63..e + 65].copy_from_slice(&[0x33, 0xc0]); // xor eax, eax
    f[e + 65..e + 69].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28]); // add rsp, 0x28
    f[e + 69] = 0x5b; // pop rbx
    f[e + 70] = 0xc3; // ret

    // ── .text: DispatchDeviceControl @0x1100 ──
    let d = 0x1100usize;
    f[d..d + 4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]); // sub rsp, 0x28
    f[d + 4..d + 6].copy_from_slice(&[0xff, 0x15]); // call [rip+..] -> IoGetCurrentIrpStackLocation
    put32(&mut f, d + 6, (0x3310u64 - (d as u64 + 10)) as u32);
    f[d + 10..d + 13].copy_from_slice(&[0x8b, 0x40, 0x10]); // mov eax,[rax+0x10]  IoControlCode
    f[d + 13..d + 18].copy_from_slice(&[0x3d, 0x40, 0xc0, 0x22, 0x00]); // cmp eax, 0x0022c040 (CTL_CODE device 0x22)
    f[d + 18..d + 20].copy_from_slice(&[0x75, 0x2a]); // jne done (0x113e)
                                                      // IOCTL 0x0022c040 matched: an attacker-sized copy whose length comes from
                                                      // InputBufferLength minus a constant (the copy-underflow the audit looks
                                                      // for), then the physical mapping the driver tests exercise.
    f[d + 20..d + 23].copy_from_slice(&[0x8b, 0x40, 0x18]); // mov eax,[rax+0x18]  InputBufferLength
    f[d + 23..d + 26].copy_from_slice(&[0x83, 0xe8, 0x04]); // sub eax, 4
    f[d + 26..d + 29].copy_from_slice(&[0x41, 0x89, 0xc0]); // mov r8d, eax  (length)
    f[d + 29..d + 32].copy_from_slice(&[0x48, 0x8d, 0x0d]); // lea rcx,[rip+..] -> 0x2010 (dst)
    put32(&mut f, d + 32, (0x2010u64 - (d as u64 + 36)) as u32);
    f[d + 36..d + 39].copy_from_slice(&[0x48, 0x8d, 0x15]); // lea rdx,[rip+..] -> 0x2090 (src)
    put32(&mut f, d + 39, (0x2090u64 - (d as u64 + 43)) as u32);
    f[d + 43..d + 45].copy_from_slice(&[0xff, 0x15]); // call [rip+..] -> RtlCopyMemory
    put32(&mut f, d + 45, (0x3320u64 - (d as u64 + 49)) as u32);
    f[d + 49..d + 52].copy_from_slice(&[0x48, 0x8d, 0x0d]); // lea rcx,[rip+..] -> 0x2010 (phys target)
    put32(&mut f, d + 52, (0x2010u64 - (d as u64 + 56)) as u32);
    f[d + 56..d + 58].copy_from_slice(&[0xff, 0x15]); // call [rip+..] -> MmMapIoSpace
    put32(&mut f, d + 58, (0x3318u64 - (d as u64 + 62)) as u32);
    f[d + 62..d + 64].copy_from_slice(&[0x33, 0xc0]); // xor eax, eax
    f[d + 64..d + 68].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
    f[d + 68] = 0xc3; // ret

    // ── .text: an unreferenced helper (0x1200) that calls an imported kernel
    // API (the ordinal slot 0x3328 = KeInitializeMutex) but is never reached
    // from the entry or any dispatch handler. Reachability analysis must mark
    // its primitive NOT user-mode reachable. ──
    let h = 0x1200usize;
    f[h..h + 4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]); // sub rsp, 0x28
    f[h + 4..h + 6].copy_from_slice(&[0xff, 0x15]); // call [rip+..] -> 0x3328
    put32(&mut f, h + 6, (0x3328u64 - (h as u64 + 10)) as u32);
    f[h + 10..h + 12].copy_from_slice(&[0x33, 0xc0]); // xor eax, eax
    f[h + 12..h + 16].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
    f[h + 16] = 0xc3; // ret

    f
}

/// A 64-bit x86_64 Mach-O that imports `puts` and binds it to a GOT slot
/// through dyld bind opcodes.
///
/// Same trick as the ELF: this exercises the whole import chain, only the
/// network here is dyld info rather than a dynamic segment: the LC_DYLD_INFO
/// command points into the file, whose bind bytecode names the symbol and
/// binds it at address 0x2000.
pub fn macho_with_bind() -> Vec<u8> {
    let mut f = vec![0u8; 0x3000];

    const PATH: &str = "/usr/lib/libSystem.B.dylib";
    // The path is padded to an 8-byte multiple so the next command is aligned;
    // the pad bytes stay zero, which terminates the string for the parser.
    let path_len = PATH.len() + 1;
    let path_padded = (path_len + 7) & !7;
    let seg_size = 72 + 80; // LC_SEGMENT_64 + one section_64
    let dylib_size = 24 + path_padded; // LC_LOAD_DYLIB + padded path
    let dyld_size = 48; // LC_DYLD_INFO_ONLY: 4 + 10 u32 pairs
    let main_size = 24; // LC_MAIN
    let total_cmds = seg_size + dylib_size + dyld_size + main_size;

    // command offsets inside the load-command area, which starts at 32
    let seg = 32usize;
    let dylib = seg + seg_size;
    let dyld = dylib + dylib_size;
    let main = dyld + dyld_size;

    // ── header ──
    put32(&mut f, 0, 0xfeed_facf); // MH_MAGIC_64, little-endian
    put32(&mut f, 4, 0x0100_0007); // CPU_TYPE_X86_64
    put32(&mut f, 8, 0x3); // cpusubtype
    put32(&mut f, 12, 0x2); // MH_EXECUTE
    put32(&mut f, 16, 4); // ncmds
    put32(&mut f, 20, total_cmds as u32); // sizeofcmds
    put32(&mut f, 24, 0x0020_0000); // MH_PIE

    // ── LC_SEGMENT_64 "__TEXT" (plus one section: __text) ──
    put32(&mut f, seg, 0x19); // LC_SEGMENT_64
    put32(&mut f, seg + 4, seg_size as u32);
    f[seg + 8..seg + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    put64(&mut f, seg + 24, 0x1000); // vmaddr
    put64(&mut f, seg + 32, 0x1000); // vmsize
    put64(&mut f, seg + 40, 0x1000); // fileoff
    put64(&mut f, seg + 48, 0x10); // filesize
    put32(&mut f, seg + 56, 0x5); // maxprot r-x
    put32(&mut f, seg + 60, 0x5); // initprot r-x
    put32(&mut f, seg + 64, 1); // nsects
    put32(&mut f, seg + 68, 0); // flags
    let s = seg + 72;
    f[s..s + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    f[s + 16..s + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    put64(&mut f, s + 32, 0x1000); // addr
    put64(&mut f, s + 40, 0x10); // size
    put32(&mut f, s + 48, 0x1000); // offset
    put32(&mut f, s + 52, 0x2); // align
    put32(&mut f, s + 56, 0); // reloff
    put32(&mut f, s + 60, 0); // nreloc
                              // S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS
    put32(&mut f, s + 64, 0x0000_0400);

    // ── LC_LOAD_DYLIB ──
    put32(&mut f, dylib, 0xc); // LC_LOAD_DYLIB
    put32(&mut f, dylib + 4, dylib_size as u32);
    put32(&mut f, dylib + 8, 24); // path offset
    put32(&mut f, dylib + 12, 0); // timestamp
    put32(&mut f, dylib + 16, 0x10000); // current version
    put32(&mut f, dylib + 20, 0x10000); // compatibility version
                                        // the trailing NUL and pad of the path are pre-zeroed in the buffer
    f[dylib + 24..dylib + 24 + PATH.len()].copy_from_slice(PATH.as_bytes());

    // ── LC_DYLD_INFO_ONLY ──
    // Layout: cmd u32, cmdsize u32, then 10 u32 (rebase, bind, weak, lazy,
    // export: each off+size), so 48 bytes total.
    put32(&mut f, dyld, 0x8000_0022);
    put32(&mut f, dyld + 4, 0x30);
    put32(&mut f, dyld + 8, 0); // rebase_off
    put32(&mut f, dyld + 12, 0); // rebase_size
    put32(&mut f, dyld + 16, 0x2200); // bind_off
    put32(&mut f, dyld + 20, 8); // bind_size
    put32(&mut f, dyld + 24, 0); // weak_bind_off
    put32(&mut f, dyld + 28, 0); // weak_bind_size
    put32(&mut f, dyld + 32, 0); // lazy_bind_off
    put32(&mut f, dyld + 36, 0); // lazy_bind_size
    put32(&mut f, dyld + 40, 0); // export_off
    put32(&mut f, dyld + 44, 0); // export_size

    // ── LC_MAIN ──
    put32(&mut f, main, 0x8000_0028); // LC_MAIN
    put32(&mut f, main + 4, main_size as u32);
    put64(&mut f, main + 8, 0x1000); // entryoff
    put64(&mut f, main + 16, 0x1000); // stacksize

    // ── bind bytecode at file offset 0x2200 ──
    // SET_SYMBOL_TRAILING_FLAGS_IMMEDIATE(0) "puts", DO_BIND, DONE.
    let b = 0x2200usize;
    f[b] = 0x40; // BIND_OPCODE_SET_SYMBOL ..., flags 0
    f[b + 1..b + 6].copy_from_slice(b"puts\0");
    f[b + 6] = 0x90; // BIND_OPCODE_DO_BIND
    f[b + 7] = 0x00; // BIND_OPCODE_DONE

    // ── __text: a few decodable instructions ──
    // mov rax, 0 (48 c7 c0 00 00 00 00); ret (c3); ud2 pad till 0x10
    f[0x1000..0x1007].copy_from_slice(&[0x48, 0xc7, 0xc0, 0, 0, 0, 0]);
    f[0x1007] = 0xc3;

    f
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

    #[test]
    fn the_pe_fixture_parses_and_imports() {
        let bytes = pe_with_iat_call();
        let bin = crate::formats::analyze("fixture.exe", &bytes).expect("parses");
        assert_eq!(bin.format, Format::Pe);
        assert_eq!(bin.bits, 64);
        assert_eq!(bin.entry, PE_TEXT);
        assert_eq!(bin.image_base, 0);
        assert!(bin.sections.iter().any(|s| s.name == ".text" && s.exec));
        let lib = bin
            .imports
            .iter()
            .find(|l| l.name == "kernel32.dll")
            .expect("the DLL is imported");
        assert_eq!(lib.functions, ["ExitProcess", "MessageBoxA"]);
        let slot = bin
            .symbols
            .iter()
            .find(|s| s.name == "kernel32!ExitProcess")
            .expect("IAT slot symbol");
        assert_eq!(slot.addr, PE_IAT);
        assert_eq!(slot.kind, SymKind::Import);
    }

    #[test]
    fn the_pe_load_config_is_parseable() {
        let bytes = pe_with_iat_call();
        let bin = crate::formats::analyze("fixture.exe", &bytes).unwrap();
        let lc = bin.hardening.load_config.expect("load config parsed");
        assert_eq!(lc.security_cookie, 0xdead_beef_cafe_f00d);
    }

    #[test]
    fn the_pe_engine_names_the_iat_call() {
        let bytes = pe_with_iat_call();
        let bin = crate::formats::analyze("fixture.exe", &bytes).unwrap();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 1000, &crate::db::Db::default());
        // The call site resolves to the IAT slot, which is one function in.
        let refs = an.xrefs_to.get(&PE_IAT).expect("the slot is referenced");
        assert!(refs
            .iter()
            .any(|x| crate::analysis::engine::XrefKind::Call == x.kind));
        // entry's function must exist and call something
        let caller = an.functions.iter().find(|f| f.addr == PE_TEXT).unwrap();
        assert_eq!(caller.calls, vec![PE_IAT]);
    }

    #[test]
    fn the_driver_fixture_parses_as_native_with_kernel_imports() {
        let bytes = pe_with_driver();
        let bin = crate::formats::analyze("fixture.sys", &bytes).expect("parses");
        assert_eq!(bin.format, Format::Pe);
        assert_eq!(bin.bits, 64);
        assert_eq!(bin.subsystem.as_deref(), Some("native"));
        assert_eq!(bin.entry, 0x1000);
        let lib = bin
            .imports
            .iter()
            .find(|l| l.name == "ntoskrnl.dll")
            .expect("ntoskrnl imported");
        assert!(lib.functions.iter().any(|n| n == "IoCreateDevice"));
        assert!(lib.functions.iter().any(|n| n == "MmMapIoSpace"));
        // The ordinal import carries its number and resolves to a real name via
        // the generated table (KeInitializeMutex is a genuine ntoskrnl export).
        assert!(lib.ordinals.iter().any(|o| o.is_some()));
        assert!(lib.functions.iter().any(|n| n == "KeInitializeMutex"));
        // .pdata seeded the two function hints.
        assert!(bin.func_hints.contains(&0x1100));
    }

    #[test]
    fn the_driver_fixture_engine_lands_on_pdata_and_kernel_sinks() {
        let bytes = pe_with_driver();
        let bin = crate::formats::analyze("fixture.sys", &bytes).unwrap();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 100_000, &crate::db::Db::default());
        assert!(an.functions.iter().any(|f| f.addr == 0x1000), "DriverEntry");
        assert!(
            an.functions.iter().any(|f| f.addr == 0x1100),
            "DispatchDeviceControl, seeded from .pdata"
        );
        // The kernel catalog is reachable through the same sink machinery.
        let hits = crate::analysis::sinks::find(&an);
        let phys = hits
            .iter()
            .find(|h| h.api == "MmMapIoSpace")
            .expect("physical-mem sink flagged from kernel catalog");
        assert!(!phys.sites.is_empty());
        let dev = hits
            .iter()
            .find(|h| h.api == "IoCreateDevice")
            .expect("device-create flagged from kernel catalog");
        assert!(!dev.sites.is_empty());
    }

    #[test]
    fn the_macho_fixture_parses_and_binds() {
        let bytes = macho_with_bind();
        let bin = crate::formats::analyze("fixture.bin", &bytes).expect("parses");
        assert_eq!(bin.format, Format::MachO);
        assert_eq!(bin.bits, 64);
        assert_eq!(bin.entry, 0x1000);
        assert!(bin
            .sections
            .iter()
            .any(|s| s.name == "__TEXT,__text" && s.exec));
        assert!(!bin.imports.is_empty(), "bind bytecode produced imports");
        assert!(bin
            .imports
            .iter()
            .flat_map(|l| l.functions.iter())
            .any(|n| n == "puts"));
        assert!(bin.libs.iter().any(|l| l.contains("libSystem")));
    }

    #[test]
    fn the_macho_engine_entries_into_text() {
        let bytes = macho_with_bind();
        let bin = crate::formats::analyze("fixture.bin", &bytes).unwrap();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 1000, &crate::db::Db::default());
        assert!(
            an.functions.iter().any(|f| f.addr == 0x1000),
            "entry function at 0x1000"
        );
    }
}
