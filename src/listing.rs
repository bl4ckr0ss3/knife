//! The shared model behind a function listing.
//!
//! Both the printed disassembly and the interactive view show the same thing:
//! blocks, labels, resolved call targets, and your notes. Building that once
//! and rendering it twice is what keeps the two from drifting apart, which
//! matters because a listing that disagrees with itself is worse than one that
//! is merely plain.

use crate::analysis::engine::{Analysis, Function};
use crate::db::Db;

/// The trailing comment on an instruction, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Annot {
    /// Something you wrote. Outranks anything derived.
    Note(String),
    /// A resolved call or branch target with a name.
    Symbol(String),
    /// A local label inside this function.
    Local(String),
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
}

impl Line {
    pub fn addr(&self) -> u64 {
        match self {
            Line::Label { addr, .. } | Line::Insn { addr, .. } => *addr,
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
pub fn function(an: &Analysis, f: &Function, db: &Db, base: u64) -> Vec<Line> {
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
            let (mnemonic, operands) = ins
                .text
                .split_once(' ')
                .map(|(m, r)| (m.to_string(), r.to_string()))
                .unwrap_or_else(|| (ins.text.clone(), String::new()));

            // Your own note outranks a derived annotation: if you wrote
            // something about this instruction, that is what you want to read.
            let annot = if let Some(n) = db.notes.get(&a.wrapping_sub(base)) {
                Some(Annot::Note(n.clone()))
            } else if let Some(name) = &ins.target_name {
                Some(Annot::Symbol(name.clone()))
            } else {
                ins.target.map(|t| {
                    let ta = t + an.display_base;
                    if an.find_function(t).is_some() {
                        Annot::Symbol(an.label(t))
                    } else {
                        Annot::Local(format!("loc_{ta:x}"))
                    }
                })
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
        let lines = function(&an, f, &Db::default(), 0);

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

        // Without a note the conditional is annotated with its local target.
        let plain = function(&an, f, &Db::default(), 0);
        assert!(matches!(
            plain.iter().find(|l| l.addr() == 0x1000),
            Some(Line::Insn {
                annot: Some(Annot::Local(_)),
                ..
            })
        ));

        let mut db = Db::default();
        db.set_note(0x1000, "bounds check");
        let noted = function(&an, f, &db, 0);
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
}
