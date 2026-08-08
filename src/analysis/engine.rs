//! The analysis engine: recursive-descent disassembly that recovers functions,
//! basic blocks, a control-flow graph, and cross-references, the backbone of
//! an interactive disassembler.
//!
//! Everything works in **virtual-address space**. PE section vaddrs are RVAs,
//! so the image base is added up front; ELF/Mach-O are already VA. That makes
//! the address column, branch operands, and symbol names all agree.

use crate::model::{Binary, Format, SymKind};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// Several fields here (instruction length/flow, block end/successors, xref
// kind) are part of the CFG model for the upcoming interactive/graph views and
// are not all read by the current text output yet.
#[allow(dead_code)]
pub struct EngineInsn {
    pub addr: u64,
    pub len: usize,
    pub text: String,
    /// A resolved symbolic target (function name / import), if any.
    pub target_name: Option<String>,
    /// A branch/call target address, if this instruction has one.
    pub target: Option<u64>,
    pub flow: FlowControl,
}

#[allow(dead_code)]
pub struct BasicBlock {
    pub start: u64,
    pub end: u64,
    pub insns: Vec<EngineInsn>,
    pub succ: Vec<u64>,
}

pub struct Function {
    pub addr: u64,
    pub name: String,
    pub blocks: Vec<BasicBlock>,
    pub size: u64,
    pub incoming: usize,
    pub calls: Vec<u64>,
    pub named: bool,
}

#[allow(dead_code)]
pub struct Xref {
    pub from: u64,
    pub kind: XrefKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    Branch,
}

pub struct Analysis {
    pub functions: Vec<Function>,
    pub xrefs_to: BTreeMap<u64, Vec<Xref>>,
    pub names: BTreeMap<u64, String>,
    /// Kept for API symmetry; addresses are already absolute, so this is 0.
    pub display_base: u64,
    #[allow(dead_code)]
    pub bits: u32,
    pub truncated: bool,
}

impl Analysis {
    pub fn label(&self, addr: u64) -> String {
        match self.names.get(&addr) {
            Some(n) => n.clone(),
            None => format!("sub_{addr:x}"),
        }
    }
    pub fn find_function(&self, addr: u64) -> Option<&Function> {
        self.functions.iter().find(|f| f.addr == addr)
    }
    pub fn find_by_name(&self, needle: &str) -> Option<&Function> {
        self.functions.iter().find(|f| f.name == needle)
    }
}

pub fn display_base(bin: &Binary) -> u64 {
    match bin.format {
        Format::Pe => bin.image_base,
        _ => 0,
    }
}

/// VA → file offset (subtract the base to get an RVA, then walk sections).
fn va_to_off(bin: &Binary, base: u64, va: u64) -> Option<usize> {
    let rva = va.checked_sub(base)?;
    for s in &bin.sections {
        let span = s.vsize.max(s.file_size);
        if s.vaddr != 0 && rva >= s.vaddr && rva < s.vaddr + span {
            return Some((s.file_off + (rva - s.vaddr)) as usize);
        }
    }
    None
}

fn in_exec(bin: &Binary, base: u64, va: u64) -> bool {
    let Some(rva) = va.checked_sub(base) else {
        return false;
    };
    bin.sections.iter().any(|s| {
        s.exec && s.file_size > 0 && rva >= s.vaddr && rva < s.vaddr + s.vsize.max(s.file_size)
    })
}

pub fn analyze(bin: &Binary, bytes: &[u8], max_insns: usize) -> Analysis {
    let base = display_base(bin);

    // Names and import slots, keyed by absolute VA.
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    let mut import_slots: BTreeMap<u64, String> = BTreeMap::new();
    for s in &bin.symbols {
        let va = s.addr + base;
        match s.kind {
            SymKind::Import => {
                import_slots.insert(va, s.name.clone());
            }
            SymKind::Func | SymKind::Export => {
                names.entry(va).or_insert_with(|| s.name.clone());
            }
        }
    }

    // Seeds: entry + every named code symbol.
    let entry_va = bin.entry + base;
    let mut seeds: VecDeque<u64> = VecDeque::new();
    let mut is_seed: BTreeSet<u64> = BTreeSet::new();
    if in_exec(bin, base, entry_va) {
        seeds.push_back(entry_va);
        is_seed.insert(entry_va);
        names.entry(entry_va).or_insert_with(|| "entry".to_string());
    }
    for s in &bin.symbols {
        let va = s.addr + base;
        if matches!(s.kind, SymKind::Func | SymKind::Export)
            && in_exec(bin, base, va)
            && is_seed.insert(va)
        {
            seeds.push_back(va);
        }
    }
    // A named symbol marks a function boundary: descent must not cross into it.
    let boundaries: BTreeSet<u64> = is_seed.iter().copied().collect();

    let mut functions: Vec<Function> = Vec::new();
    let mut xrefs_to: BTreeMap<u64, Vec<Xref>> = BTreeMap::new();
    let mut done: BTreeSet<u64> = BTreeSet::new();
    let mut budget = max_insns;
    let mut truncated = false;

    while let Some(func_va) = seeds.pop_front() {
        if done.contains(&func_va) {
            continue;
        }
        if budget == 0 {
            truncated = true;
            break;
        }
        done.insert(func_va);

        let (func, discovered, spent) = build_function(
            bin,
            bytes,
            func_va,
            base,
            &names,
            &import_slots,
            &boundaries,
            &mut xrefs_to,
            budget,
        );
        budget = budget.saturating_sub(spent);

        for c in discovered {
            if in_exec(bin, base, c) && is_seed.insert(c) {
                seeds.push_back(c);
            }
        }
        if func.size > 0 {
            functions.push(func);
        }
    }

    let mut incoming: BTreeMap<u64, usize> = BTreeMap::new();
    for (target, refs) in &xrefs_to {
        incoming.insert(*target, refs.len());
    }
    for f in &mut functions {
        f.incoming = incoming.get(&f.addr).copied().unwrap_or(0);
        f.named = names.contains_key(&f.addr);
        if !f.named {
            f.name = format!("sub_{:x}", f.addr);
        }
    }
    functions.sort_by_key(|f| f.addr);

    Analysis {
        functions,
        xrefs_to,
        names,
        display_base: 0,
        bits: bin.bits,
        truncated,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_function(
    bin: &Binary,
    bytes: &[u8],
    entry: u64,
    base: u64,
    names: &BTreeMap<u64, String>,
    import_slots: &BTreeMap<u64, String>,
    boundaries: &BTreeSet<u64>,
    xrefs_to: &mut BTreeMap<u64, Vec<Xref>>,
    budget: usize,
) -> (Function, Vec<u64>, usize) {
    let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
    let mut worklist: VecDeque<u64> = VecDeque::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut calls: Vec<u64> = Vec::new();
    let mut spent = 0usize;
    let mut min_start = entry;
    let mut max_end = entry;

    // A block target inside this function that is not another function's entry.
    let queue_block = |t: u64, seen: &mut BTreeSet<u64>, wl: &mut VecDeque<u64>| -> bool {
        // never absorb another named function's body
        if t != entry && boundaries.contains(&t) {
            return false;
        }
        if va_to_off(bin, base, t).is_none() {
            return false;
        }
        if seen.insert(t) {
            wl.push_back(t);
        }
        true
    };

    worklist.push_back(entry);
    seen.insert(entry);

    while let Some(block_start) = worklist.pop_front() {
        if spent >= budget {
            break;
        }
        let Some(off) = va_to_off(bin, base, block_start) else {
            continue;
        };
        min_start = min_start.min(block_start);
        let mut decoder =
            Decoder::with_ip(bin.bits, &bytes[off..], block_start, DecoderOptions::NONE);
        let mut insns = Vec::new();
        let mut succ = Vec::new();
        let mut end = block_start;

        loop {
            if !decoder.can_decode() || spent >= budget {
                break;
            }
            let insn = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            spent += 1;
            let addr = insn.ip();
            let len = insn.len();
            end = addr + len as u64;
            max_end = max_end.max(end);

            let flow = insn.flow_control();
            let mut target = None;
            let mut target_name = None;

            let is_near_branch = matches!(
                insn.op0_kind(),
                iced_x86::OpKind::NearBranch16
                    | iced_x86::OpKind::NearBranch32
                    | iced_x86::OpKind::NearBranch64
            );

            match flow {
                FlowControl::Call if is_near_branch => {
                    let t = insn.near_branch_target();
                    target = Some(t);
                    target_name = names.get(&t).cloned();
                    calls.push(t);
                    xrefs_to.entry(t).or_default().push(Xref {
                        from: addr,
                        kind: XrefKind::Call,
                    });
                }
                FlowControl::UnconditionalBranch if is_near_branch => {
                    let t = insn.near_branch_target();
                    target = Some(t);
                    target_name = names.get(&t).cloned();
                    let kind = XrefKind::Jump;
                    xrefs_to
                        .entry(t)
                        .or_default()
                        .push(Xref { from: addr, kind });
                    // tail-call to another function, or an intra-function jump?
                    if boundaries.contains(&t) && t != entry {
                        calls.push(t); // treat as a tail call
                    } else if queue_block(t, &mut seen, &mut worklist) {
                        succ.push(t);
                    }
                }
                FlowControl::ConditionalBranch if is_near_branch => {
                    let t = insn.near_branch_target();
                    target = Some(t);
                    target_name = names.get(&t).cloned();
                    xrefs_to.entry(t).or_default().push(Xref {
                        from: addr,
                        kind: XrefKind::Branch,
                    });
                    if queue_block(t, &mut seen, &mut worklist) {
                        succ.push(t);
                    }
                }
                FlowControl::Call | FlowControl::UnconditionalBranch
                    if insn.is_ip_rel_memory_operand() =>
                {
                    // call/jmp [rip+disp]: resolve through the IAT when the slot
                    // is a known import. (Note: some toolchains route calls via
                    // first-thunk addresses the importer table does not expose;
                    // those resolve to sub_ names for now.)
                    let slot = insn.ip_rel_memory_address();
                    if let Some(n) = import_slots.get(&slot) {
                        target = Some(slot);
                        target_name = Some(n.clone());
                        if flow == FlowControl::Call {
                            xrefs_to.entry(slot).or_default().push(Xref {
                                from: addr,
                                kind: XrefKind::Call,
                            });
                        }
                    }
                }
                _ => {}
            }

            let text = format_insn(&insn);
            insns.push(EngineInsn {
                addr,
                len,
                text,
                target_name,
                target,
                flow,
            });

            // A conditional branch also falls through to the next instruction.
            if flow == FlowControl::ConditionalBranch {
                if queue_block(end, &mut seen, &mut worklist) {
                    succ.push(end);
                }
                break;
            }
            let stop = matches!(
                flow,
                FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::Interrupt
            ) || insn.mnemonic() == Mnemonic::Int3
                // stop if we are about to run into another function's entry
                || boundaries.contains(&end) && end != entry;
            if stop {
                break;
            }
        }

        blocks.insert(
            block_start,
            BasicBlock {
                start: block_start,
                end,
                insns,
                succ,
            },
        );
    }

    let name = names
        .get(&entry)
        .cloned()
        .unwrap_or_else(|| format!("sub_{entry:x}"));
    let discovered = calls.clone();
    let func = Function {
        addr: entry,
        name,
        blocks: blocks.into_values().collect(),
        size: max_end.saturating_sub(min_start),
        incoming: 0,
        calls,
        named: names.contains_key(&entry),
    };
    (func, discovered, spent)
}

fn format_insn(insn: &Instruction) -> String {
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_uppercase_hex(false);
    fmt.options_mut().set_hex_prefix("0x");
    fmt.options_mut().set_hex_suffix("");
    fmt.options_mut().set_space_after_operand_separator(true);
    let mut s = String::new();
    fmt.format(insn, &mut s);
    s
}
