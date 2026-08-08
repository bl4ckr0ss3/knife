//! The shared model behind a function listing.
//!
//! Both the printed disassembly and the interactive view show the same thing:
//! blocks, labels, resolved call targets, and your notes. Building that once
//! and rendering it twice is what keeps the two from drifting apart, which
//! matters because a listing that disagrees with itself is worse than one that
//! is merely plain.

use crate::analysis::engine::{Analysis, Function, XrefKind};
use crate::analysis::strings::{self, Located};
use crate::db::Db;
use crate::model::Binary;
use std::collections::BTreeMap;

/// The trailing comment on an instruction, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Annot {
    /// Something you wrote. Outranks anything derived.
    Note(String),
    /// A resolved call or branch target with a name.
    Symbol(String),
    /// A local label inside this function.
    Local(String),
    /// A string literal an operand points at, quoted by the renderer.
    Text(String),
}

#[derive(Debug, Clone)]
pub enum Line {
    /// A branch target inside the function, printed as its own line.
    Label { addr: u64, text: String },
    Insn {
        addr: u64,
        mnemonic: String,
        operands: String,
        annot: Option<Annot>,
        /// Where the instruction goes, when following it makes sense.
        target: Option<u64>,
    },
    /// A raw dump row (hex + ascii) when the view is showing data, not code.
    Data { addr: u64, text: String },
}

impl Line {
    pub fn addr(&self) -> u64 {
        match self {
            Line::Label { addr, .. } | Line::Insn { addr, .. } | Line::Data { addr, .. } => *addr,
        }
    }
    pub fn target(&self) -> Option<u64> {
        match self {
            Line::Insn { target, .. } => *target,
            _ => None,
        }
    }
}

/// Render one recovered function into lines.
///
/// `base` converts an address into the space the database stores, so notes
/// attach to the right instruction whatever the image base is.
pub fn function(
    an: &Analysis,
    f: &Function,
    db: &Db,
    base: u64,
    strings: &BTreeMap<u64, Located>,
) -> Vec<Line> {
    let mut out = Vec::new();
    for (i, block) in f.blocks.iter().enumerate() {
        if i > 0 {
            out.push(Line::Label {
                addr: block.start,
                text: format!("loc_{:x}", block.start + an.display_base),
            });
        }
        for ins in &block.insns {
            let a = ins.addr + an.display_base;
            let text = ins.text(an.bits, an.arch);
            let (mnemonic, operands) = text
                .split_once(' ')
                .map(|(m, r)| (m.to_string(), r.to_string()))
                .unwrap_or_else(|| (text.clone(), String::new()));

            // Your own note outranks a derived annotation: if you wrote
            // something about this instruction, that is what you want to read.
            let annot = if let Some(n) = db.notes.get(&a.wrapping_sub(base)) {
                Some(Annot::Note(n.clone()))
            } else if let Some(name) = &ins.target_name {
                Some(Annot::Symbol(name.clone()))
            } else if let Some(t) = ins.target {
                let ta = t + an.display_base;
                if an.find_function(t).is_some() {
                    Some(Annot::Symbol(an.label(t)))
                } else {
                    Some(Annot::Local(format!("loc_{ta:x}")))
                }
            } else {
                string_annot(an, strings, ins.addr)
            };

            out.push(Line::Insn {
                addr: ins.addr,
                mnemonic,
                operands,
                annot,
                target: ins.target,
            });
        }
    }
    out
}

/// Everything this instruction points at that lands inside a string literal,
/// rendered as the literal itself.
fn string_annot(an: &Analysis, strings: &BTreeMap<u64, Located>, addr: u64) -> Option<Annot> {
    for r in an.xrefs_from.get(&addr)? {
        if r.kind != XrefKind::Data {
            continue;
        }
        // A data ref may point mid-string; only check it lies within the
        // span. The range lookup finds the literal starting closest before it.
        if let Some((start, s)) = strings.range(..=r.to).next_back() {
            if *start <= r.to && r.to < start + s.len {
                return Some(Annot::Text(s.text.clone()));
            }
        }
    }
    None
}

/// The literals of the image, keyed by virtual address, for `function`'s
/// annotations and for jumping into a string from the interactive view.
pub fn string_map(bin: &Binary, bytes: &[u8], base: u64) -> BTreeMap<u64, Located> {
    let mut out = BTreeMap::new();
    for s in strings::extract_located(bytes, 4) {
        if let Some(va) = crate::analysis::engine::off_to_va(bin, base, s.off) {
            out.insert(va, s);
        }
    }
    out
}

/// A hex dump of the bytes at an address, laid out like the function listing
/// so the same pane can switch between code and data without a mode change.
pub fn data_view(bin: &Binary, base: u64, bytes: &[u8], addr: u64) -> Vec<Line> {
    let Some(off) = crate::analysis::engine::va_to_off(bin, base, addr) else {
        return vec![Line::Data {
            addr,
            text: format!("0x{addr:x} is not in any mapped section"),
        }];
    };

    let mut out = Vec::new();
    for (row, chunk) in bytes[off..].chunks(16).enumerate().take(8) {
        let hex: String = chunk
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let sep = if i == 15 {
                    ""
                } else if i == 7 {
                    "  "
                } else {
                    " "
                };
                format!("{b:02x}{sep}")
            })
            .collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push(Line::Data {
            addr: addr + (row as u64) * 16,
            text: format!("{hex:<48} {ascii}"),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::engine;
    use crate::model::{Arch, Binary, Format, Section};

    fn code_at(vaddr: u64, code: &[u8]) -> (Binary, Vec<u8>) {
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.entry = vaddr;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr,
            vsize: code.len() as u64,
            file_off: vaddr,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let mut bytes = vec![0u8; vaddr as usize];
        bytes.extend_from_slice(code);
        (bin, bytes)
    }

    #[test]
    fn a_branch_target_gets_its_own_label_line() {
        let code = [
            0x31, 0xc0, // xor eax, eax
            0x74, 0x02, // je +2
            0x90, 0x90, // nop; nop
            0xc3, // ret
        ];
        let (bin, bytes) = code_at(0x1000, &code);
        let an = engine::analyze(&bin, &bytes, 1000, &Db::default());
        let f = an.find_function(0x1000).unwrap();
        let lines = function(&an, f, &Db::default(), 0, &string_map(&bin, &bytes, 0));

        assert!(
            lines.iter().any(|l| matches!(l, Line::Label { .. })),
            "a branch target should produce a label"
        );
        // Every instruction appears exactly once, mirroring the split blocks.
        let mut addrs: Vec<u64> = lines
            .iter()
            .filter(|l| matches!(l, Line::Insn { .. }))
            .map(Line::addr)
            .collect();
        let n = addrs.len();
        addrs.sort_unstable();
        addrs.dedup();
        assert_eq!(n, addrs.len());
    }

    #[test]
    fn a_note_replaces_the_derived_annotation() {
        let code = [0x74, 0x00, 0xc3]; // je +0 ; ret
        let (bin, bytes) = code_at(0x1000, &code);
        let an = engine::analyze(&bin, &bytes, 1000, &Db::default());
        let f = an.find_function(0x1000).unwrap();
        let strings = string_map(&bin, &bytes, 0);

        // Without a note the conditional is annotated with its local target.
        let plain = function(&an, f, &Db::default(), 0, &strings);
        assert!(matches!(
            plain.iter().find(|l| l.addr() == 0x1000),
            Some(Line::Insn {
                annot: Some(Annot::Local(_)),
                ..
            })
        ));

        let mut db = Db::default();
        db.set_note(0x1000, "bounds check");
        let noted = function(&an, f, &db, 0, &strings);
        assert_eq!(
            noted.iter().find(|l| l.addr() == 0x1000).and_then(|l| {
                match l {
                    Line::Insn { annot, .. } => annot.clone(),
                    _ => None,
                }
            }),
            Some(Annot::Note("bounds check".into()))
        );
    }

    #[test]
    fn a_string_operand_is_annotated_with_the_literal() {
        // lea rax, [rip+0x17] names 0x101e, where "hello" sits in .rodata.
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.entry = 0x1000;
        bin.sections = vec![
            Section {
                name: ".text".into(),
                vaddr: 0x1000,
                vsize: 8,
                file_off: 0,
                file_size: 8,
                entropy: 0.0,
                read: true,
                write: false,
                exec: true,
            },
            Section {
                name: ".rodata".into(),
                vaddr: 0x101e,
                vsize: 5,
                file_off: 8,
                file_size: 5,
                entropy: 0.0,
                read: true,
                write: false,
                exec: false,
            },
        ];
        let mut bytes = vec![0x48, 0x8d, 0x05, 0x17, 0x00, 0x00, 0x00, 0xc3];
        bytes.extend_from_slice(b"hello");
        let an = engine::analyze(&bin, &bytes, 1000, &Db::default());
        let f = an.find_function(0x1000).unwrap();
        let lines = function(&an, f, &Db::default(), 0, &string_map(&bin, &bytes, 0));

        let annot = lines
            .iter()
            .find(|l| l.addr() == 0x1000)
            .and_then(|l| match l {
                Line::Insn { annot, .. } => annot.clone(),
                _ => None,
            });
        assert_eq!(annot, Some(Annot::Text("hello".into())));
    }

    #[test]
    fn data_view_rows_start_at_the_requested_address() {
        let (bin, bytes) = code_at(0x1000, &[0x90, 0xc3, 0x90, 0x90]);
        let lines = data_view(&bin, 0, &bytes, 0x1000);
        assert_eq!(lines[0].addr(), 0x1000);
        assert!(matches!(lines[0], Line::Data { .. }));
    }
}
