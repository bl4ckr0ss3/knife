//! Forwarding-stub resolution: turning `call sub_401f20` into `call strcpy`.
//!
//! Neither format calls an imported function directly. ELF routes the call
//! through a `.plt` stub that jumps via a GOT slot, and PE linkers emit the
//! same shape as `jmp [IAT]` thunks in the text section. On x86/AMD64 both are
//! one `jmp [slot]`; on AArch64 the stub is a three-instruction page load:
//! `adrp x16/x17, page; ldr x17/x16, [xN, #lo]; br xM`. The import tables
//! already told us what lives at each slot, so one pass names every stub in
//! either shape.
//!
//! The scans match the fixed opcode patterns by hand rather than disassembling
//! whole sections, because the stub tables are small and the instructions are
//! fixed width. False positives are filtered by construction: a stray pattern
//! in the middle of some other instruction only survives if its displacement
//! happens to land exactly on a known import slot.

use crate::model::{Arch, Binary, Format, SymKind, Symbol};

/// `endbr64`, emitted at the head of a CET-compatible stub.
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];
/// `endbr32`, the 32-bit spelling.
const ENDBR32: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfb];
/// `bti c`, the AArch64 speculative-branch guard at the head of a stub.
const BTIC: u32 = 0xd503_245f;

/// Scan the executable sections for stubs that jump through a known import
/// slot, and return one `Thunk` symbol per stub found.
///
/// `base` is the value that turns a section vaddr into the address space the
/// engine works in (the image base for PE, zero elsewhere).
pub fn resolve(bin: &Binary, bytes: &[u8], base: u64) -> Vec<Symbol> {
    // slot address (absolute) -> import name
    let slots: std::collections::BTreeMap<u64, &str> = bin
        .symbols
        .iter()
        .filter(|s| s.kind == SymKind::Import)
        .map(|s| (s.addr + base, s.name.as_str()))
        .collect();
    if slots.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for sec in bin.sections.iter().filter(|s| s.exec && s.file_size > 0) {
        let start = sec.file_off as usize;
        let end = (start + sec.file_size as usize).min(bytes.len());
        if start >= end {
            continue;
        }
        let data = &bytes[start..end];
        let sec_va = sec.vaddr + base;

        if bin.arch == Arch::Aarch64 {
            out.extend(scan_aarch64(data, sec_va, &slots, &mut seen, base));
        } else {
            scan_x86(
                data, sec_va, bin.bits, bin.format, base, &slots, &mut out, &mut seen,
            );
        }
    }
    out
}

/// The x86/AMD64 shape: `jmp [slot]`, six fixed bytes plus the exact one-byte
/// prefixes a linker may attach. See the module comment for the scan rationale.
#[allow(clippy::too_many_arguments)]
fn scan_x86(
    data: &[u8],
    sec_va: u64,
    bits: u32,
    format: Format,
    base: u64,
    slots: &std::collections::BTreeMap<u64, &str>,
    out: &mut Vec<Symbol>,
    seen: &mut std::collections::BTreeSet<u64>,
) {
    // `ff 25` is `jmp [mem]`: RIP-relative on x86-64, absolute on x86.
    let mut i = 0usize;
    while i + 6 <= data.len() {
        if data[i] != 0xff || data[i + 1] != 0x25 {
            i += 1;
            continue;
        }
        let disp = i32::from_le_bytes([data[i + 2], data[i + 3], data[i + 4], data[i + 5]]);

        // The displacement is measured from the end of the instruction,
        // which is always six bytes past the opcode regardless of how many
        // prefixes precede it.
        let insn_end = sec_va + (i as u64) + 6;
        let slot = if bits == 64 {
            insn_end.wrapping_add(disp as i64 as u64)
        } else {
            disp as u32 as u64
        };

        let Some(name) = slots.get(&slot) else {
            i += 1;
            continue;
        };

        // Walk back over a `bnd`/REX prefix and an `endbr` guard to find
        // where the stub actually begins, since that is the address a call
        // targets.
        let mut stub = i;
        if stub > 0 && matches!(data[stub - 1], 0xf2 | 0x48 | 0x66) {
            stub -= 1;
        }
        if stub >= 4 {
            let prev = &data[stub - 4..stub];
            if prev == ENDBR64 || prev == ENDBR32 {
                stub -= 4;
            }
        }

        let addr = sec_va + stub as u64;
        if seen.insert(addr) {
            out.push(Symbol {
                addr: addr - base, // symbols are stored pre-base, like the rest
                name: decorate(format, name),
                kind: SymKind::Thunk,
            });
        }
        i += 6;
    }
}

/// The AArch64 shape: `adrp xN, page; ldr xM, [xN, #lo]; br xM`, the page
/// loaded from the GOT slot the relocation named. Both register spellings the
/// toolchains actually emit are matched, an optional `bti c` guard is
/// absorbed into the stub head, and a slot that no import named is not a
/// veneer — the same two-sided contract the x86 scan keeps.
fn scan_aarch64(
    data: &[u8],
    sec_va: u64,
    slots: &std::collections::BTreeMap<u64, &str>,
    seen: &mut std::collections::BTreeSet<u64>,
    base: u64,
) -> Vec<Symbol> {
    let w = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
    let mut found = Vec::new();
    let mut i = 0usize;
    while i + 12 <= data.len() {
        let w0 = w(i);
        let w1 = w(i + 4);
        let w2 = w(i + 8);
        if !is_veneer(w0, w1, w2) {
            i += 1;
            continue;
        }
        // adrp: X[d] = Align(PC, 4096) + (imm21 << 12), where PC is the address
        // of the adrp itself, not the next instruction. (The `+4` mistake only
        // bites when the adrp sits in a page's last word, but that is exactly
        // the kind of edge a scanner should not get wrong.)
        let imm = (((w0 >> 5) & 0x7ffff) << 2) | ((w0 >> 29) & 3);
        let page =
            ((sec_va + i as u64) & !0xfffu64).wrapping_add_signed(sext(imm as u64, 21) << 12);
        let slot = page + ((((w1 >> 10) & 0xfff) << 3) as u64);

        let Some(name) = slots.get(&slot) else {
            i += 1;
            continue;
        };

        // Absorb a leading `bti c` guard; a call then lands on the stub head.
        let mut stub = i;
        if stub >= 4 && w(stub - 4) == BTIC {
            stub -= 4;
        }
        if seen.insert(sec_va + stub as u64) {
            found.push(Symbol {
                addr: sec_va + stub as u64 - base, // pre-base, like the rest
                name: decorate(Format::Elf, name),
                kind: SymKind::Thunk,
            });
        }
        i += 4;
    }
    found
}

/// True when `w0 w1 w2` is a GOT veneer: `adrp ra, pg; ldr rt, [ra, #lo];
/// br rt` with ra, rt in {x16, x17} — the only registers the ABI allows an
/// intra-procedure-call sequence to clobber, which is what binds the search
/// to real linker output.
fn is_veneer(w0: u32, w1: u32, w2: u32) -> bool {
    let is_adrp = |w: u32| (w & 0x9f00_0000) == 0x9000_0000;
    let is_ldr64_off = |w: u32| (w & 0xffc0_0000) == 0xf940_0000;
    let is_br = |w: u32| (w & 0xffff_fc1f) == 0xd61f_0000;
    if !(is_adrp(w0) && is_ldr64_off(w1) && is_br(w2)) {
        return false;
    }
    let ra = w0 & 0x1f;
    let rt = w1 & 0x1f;
    let scratch = |r: u32| r == 16 || r == 17;
    scratch(ra)
        && scratch(rt)
        && ra != rt
        && ((w1 >> 5) & 0x1f) == ra // the ldr indexes the adrp target
        && ((w2 >> 5) & 0x1f) == rt // the br branches what the ldr loaded
}

fn sext(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

/// ELF tooling has called these `name@plt` for decades and a researcher reads
/// that instantly; PE import names already carry their module, so they are left
/// alone.
fn decorate(format: Format, name: &str) -> String {
    match format {
        Format::Elf => format!("{name}@plt"),
        _ => name.to_string(),
    }
}

/// The import a thunk name refers to, with the decoration removed: `strcpy@plt`
/// and `KERNEL32!lstrcpyA` both reduce to the bare API name so a sink catalogue
/// can match either.
pub fn bare_name(name: &str) -> &str {
    let n = name.strip_suffix("@plt").unwrap_or(name);
    let n = n.rsplit_once('!').map(|(_, f)| f).unwrap_or(n);
    n.strip_prefix('_').unwrap_or(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Arch, Section};

    fn sec(name: &str, vaddr: u64, off: u64, size: u64) -> Section {
        Section {
            name: name.into(),
            vaddr,
            vsize: size,
            file_off: off,
            file_size: size,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }
    }

    #[test]
    fn resolves_a_rip_relative_plt_stub() {
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.sections = vec![sec(".plt", 0x1000, 0, 16)];
        bin.symbols = vec![Symbol {
            addr: 0x2000,
            name: "strcpy".into(),
            kind: SymKind::Import,
        }];
        // jmp [rip+0xffa] at 0x1000: ends at 0x1006, so it targets 0x2000.
        let mut bytes = vec![0u8; 16];
        bytes[0] = 0xff;
        bytes[1] = 0x25;
        bytes[2..6].copy_from_slice(&0x0ffai32.to_le_bytes());

        let found = resolve(&bin, &bytes, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addr, 0x1000);
        assert_eq!(found[0].name, "strcpy@plt");
    }

    #[test]
    fn stub_start_walks_back_over_endbr_and_bnd() {
        // A CET `.plt.sec` entry is `endbr64; bnd jmp [rip+X]`, and a call
        // targets the endbr64, not the jump.
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.sections = vec![sec(".plt.sec", 0x1000, 0, 16)];
        bin.symbols = vec![Symbol {
            addr: 0x2000,
            name: "memcpy".into(),
            kind: SymKind::Import,
        }];
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&ENDBR64);
        bytes[4] = 0xf2; // bnd
        bytes[5] = 0xff;
        bytes[6] = 0x25;
        // jmp opcode at offset 5, so the instruction ends at 0x100b.
        bytes[7..11].copy_from_slice(&0x0ff5i32.to_le_bytes());

        let found = resolve(&bin, &bytes, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addr, 0x1000, "stub should start at the endbr64");
        assert_eq!(found[0].name, "memcpy@plt");
    }

    #[test]
    fn a_displacement_that_hits_nothing_is_not_a_thunk() {
        // The `ff 25` pattern occurs inside ordinary code; only a displacement
        // landing exactly on a known slot may be treated as a stub.
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.sections = vec![sec(".text", 0x1000, 0, 16)];
        bin.symbols = vec![Symbol {
            addr: 0x2000,
            name: "strcpy".into(),
            kind: SymKind::Import,
        }];
        let mut bytes = vec![0u8; 16];
        bytes[0] = 0xff;
        bytes[1] = 0x25;
        bytes[2..6].copy_from_slice(&0x1234i32.to_le_bytes());
        assert!(resolve(&bin, &bytes, 0).is_empty());
    }

    #[test]
    fn x86_uses_an_absolute_slot_address() {
        let mut bin = Binary::stub(Format::Elf, Arch::X86);
        bin.sections = vec![sec(".plt", 0x1000, 0, 16)];
        bin.symbols = vec![Symbol {
            addr: 0x8049000,
            name: "system".into(),
            kind: SymKind::Import,
        }];
        let mut bytes = vec![0u8; 16];
        bytes[0] = 0xff;
        bytes[1] = 0x25;
        bytes[2..6].copy_from_slice(&0x0804_9000u32.to_le_bytes());
        let found = resolve(&bin, &bytes, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "system@plt");
    }

    #[test]
    fn names_a_plt_call_end_to_end() {
        // The whole chain on a real (if small) ELF: .text calls a .plt stub,
        // the stub jumps through a GOT slot, and a relocation binds that slot
        // to `strcpy`. The call site should read as the library function.
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 10_000, &crate::db::Db::default());

        let stub = an
            .names
            .iter()
            .find(|(_, n)| n.as_str() == "strcpy@plt")
            .map(|(a, _)| *a)
            .expect("the PLT stub should be named after its import");

        // The import map keeps the decorated name so it can be displayed, and
        // reduces to the bare API name only when matching.
        let full = an.imports.get(&stub).expect("stub is a known import");
        assert_eq!(full, "strcpy@plt");
        assert_eq!(bare_name(full), "strcpy");
        // An import is reachable through both its stub and its GOT slot, and
        // resolution returns both so a cross-reference search is complete.
        let found = an.resolve("strcpy", None);
        assert!(found.contains(&stub), "the stub resolves");
        assert_eq!(found.len(), 2, "stub and slot: {found:x?}");

        // And the call site in .text should point at it.
        let entry = an.find_function(bin.entry).expect("entry recovered");
        let call = entry
            .blocks
            .iter()
            .flat_map(|b| b.insns.iter())
            .find(|i| i.target == Some(stub))
            .expect("the entry function calls the stub");
        assert_eq!(call.target_name.as_deref(), Some("strcpy@plt"));
        assert!(
            an.xrefs_to.contains_key(&stub),
            "the call is cross-referenced"
        );
    }

    #[test]
    fn names_an_aarch64_veneer_call_end_to_end() {
        // The same chain as the x86 test, on AArch64: .text `bl`s the veneer,
        // the veneer loads the GOT slot via adrp/ldr/br, and a JUMP_SLOT
        // relocation binds the slot to `strcpy`.
        let bytes = crate::formats::fixture::elf_aarch64_plt_call();
        let bin = crate::formats::analyze("fixture-a64.elf", &bytes).unwrap();
        assert_eq!(bin.arch, Arch::Aarch64);

        let an = crate::analysis::engine::analyze(&bin, &bytes, 10_000, &crate::db::Db::default());
        let stub = an
            .names
            .iter()
            .find(|(_, n)| n.as_str() == "strcpy@plt")
            .map(|(a, _)| *a)
            .expect("the veneer should be named after its import");

        // The bl in the entry function should resolve to the veneer by name.
        let entry = an.find_function(bin.entry).expect("entry recovered");
        let call = entry
            .blocks
            .iter()
            .flat_map(|b| b.insns.iter())
            .find(|i| i.target == Some(stub))
            .expect("the entry function calls the veneer");
        assert_eq!(call.target_name.as_deref(), Some("strcpy@plt"));
    }

    #[test]
    fn a_stored_name_overrides_the_derived_one_and_seeds_a_function() {
        // Naming an address is how you tell the engine there is a function
        // there, so it has to both rename and create work.
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();

        let mut db = crate::db::Db::default();
        db.set_name(bin.entry, "parse_header");
        let an = crate::analysis::engine::analyze(&bin, &bytes, 10_000, &db);

        assert_eq!(an.label(bin.entry), "parse_header");
        let f = an
            .find_by_name("parse_header")
            .expect("named and recovered");
        assert_eq!(f.addr, bin.entry);
        assert!(f.named, "a stored name counts as named");
    }

    #[test]
    fn bare_name_strips_both_decorations() {
        assert_eq!(bare_name("strcpy@plt"), "strcpy");
        assert_eq!(bare_name("KERNEL32!lstrcpyA"), "lstrcpyA");
        assert_eq!(bare_name("_memcpy"), "memcpy");
        assert_eq!(bare_name("system"), "system");
    }
}
