//! Forwarding-stub resolution: turning `call sub_401f20` into `call strcpy`.
//!
//! Neither format calls an imported function directly. ELF routes the call
//! through a `.plt` stub that jumps via a GOT slot, and PE linkers emit the
//! same shape as `jmp [IAT]` thunks in the text section. Both are one
//! instruction, `jmp [slot]`, and the import tables already told us what lives
//! at each slot, so a single pass names every stub in either format.
//!
//! The scan matches the `ff 25` opcode by hand rather than disassembling whole
//! sections, because the stub tables are small and the instruction is fixed
//! width. False positives are filtered by construction: a stray `ff 25` in the
//! middle of some other instruction only survives if its displacement happens
//! to land exactly on a known import slot.

use crate::model::{Binary, Format, SymKind, Symbol};

/// `endbr64`, emitted at the head of a CET-compatible stub.
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];
/// `endbr32`, the 32-bit spelling.
const ENDBR32: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfb];

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
            let slot = if bin.bits == 64 {
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
                    name: decorate(bin.format, name),
                    kind: SymKind::Thunk,
                });
            }
            i += 6;
        }
    }
    out
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
