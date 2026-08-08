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
    /// An instruction that names an address without transferring control to it:
    /// `lea rax, [rip+str]`, a global load, a function pointer being taken.
    Data,
}

impl XrefKind {
    pub fn label(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jmp",
            XrefKind::Branch => "branch",
            XrefKind::Data => "data",
        }
    }
}

pub struct Analysis {
    pub functions: Vec<Function>,
    pub xrefs_to: BTreeMap<u64, Vec<Xref>>,
    pub names: BTreeMap<u64, String>,
    /// Every address that reaches an imported function, whether it is a PLT/ILT
    /// stub or the import slot itself, mapped to its full decorated name. This
    /// is the lookup that turns "where is `strcpy` called" into a set of
    /// addresses to pull cross-references for.
    pub imports: BTreeMap<u64, String>,
    /// Kept for API symmetry; addresses are already absolute, so this is 0.
    pub display_base: u64,
    #[allow(dead_code)]
    pub bits: u32,
    pub truncated: bool,
}

impl Analysis {
    pub fn label(&self, addr: u64) -> String {
        // Import slots have a name but no code, so they are not in `names`;
        // without this fallback an IAT entry renders as an anonymous `sub_`.
        match self.names.get(&addr).or_else(|| self.imports.get(&addr)) {
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

    /// The function whose body contains `addr`, which is how a cross-reference
    /// address becomes "inside `parse_header`" rather than a bare number.
    pub fn function_at(&self, addr: u64) -> Option<&Function> {
        self.functions
            .iter()
            .find(|f| f.blocks.iter().any(|b| addr >= b.start && addr < b.end))
    }

    /// Every address a selector could mean.
    ///
    /// One name can legitimately map to several addresses: an imported API is
    /// reachable through both its stub and its slot, and the same API may be
    /// imported from more than one module. Returning all of them is what makes
    /// "who calls `memcpy`" complete rather than merely plausible.
    pub fn resolve(&self, sel: &str, literal: Option<u64>) -> Vec<u64> {
        let mut out: Vec<u64> = Vec::new();
        let push = |a: u64, out: &mut Vec<u64>| {
            if !out.contains(&a) {
                out.push(a);
            }
        };

        for (addr, name) in &self.names {
            if name == sel {
                push(*addr, &mut out);
            }
        }
        // Imports match on the bare API name, so `strcpy` finds `strcpy@plt`
        // and `KERNEL32!lstrcpyA` alike.
        for (addr, name) in &self.imports {
            if crate::analysis::thunks::bare_name(name).eq_ignore_ascii_case(sel) {
                push(*addr, &mut out);
            }
        }
        // A bare address is only used when nothing was named, so a symbol that
        // happens to look like a number still wins.
        if out.is_empty() {
            if let Some(v) = literal {
                push(v, &mut out);
            }
        }
        out
    }
}

/// A call chain from an entry point to a target, as a list of addresses.
pub type Path = Vec<u64>;

impl Analysis {
    /// Shortest call chains that reach `target`.
    ///
    /// The search runs backwards from the target over call edges, because the
    /// question being asked is "what can get here", and a reverse breadth-first
    /// walk answers it in one pass while naturally yielding shortest paths.
    ///
    /// `strict` decides what counts as the start of a chain. When a caller asks
    /// about specific roots it means them literally, so only chains arriving at
    /// one are reported. When the roots are just "the entry point and the
    /// exports", a function that nothing calls also counts, because static
    /// analysis routinely misses indirect callers and dropping those chains
    /// would hide real reachability rather than prove its absence.
    pub fn paths_to(
        &self,
        target: u64,
        roots: &[u64],
        max_paths: usize,
        strict: bool,
    ) -> Vec<Path> {
        // Callee -> callers, built from the recovered call edges.
        let mut callers: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for f in &self.functions {
            for c in &f.calls {
                callers.entry(*c).or_default().insert(f.addr);
            }
        }
        let root_set: BTreeSet<u64> = roots.iter().copied().collect();

        let mut out: Vec<Path> = Vec::new();
        let mut visited: BTreeSet<u64> = BTreeSet::new();
        // Each queue item is a full chain ending at the target, held in
        // reverse; the frontier is its first element.
        let mut queue: VecDeque<Path> = VecDeque::new();
        queue.push_back(vec![target]);
        visited.insert(target);

        while let Some(chain) = queue.pop_front() {
            if out.len() >= max_paths {
                break;
            }
            let head = chain[0];
            let ups = callers.get(&head);
            let is_root = root_set.contains(&head);
            let unreached = ups.is_none_or(BTreeSet::is_empty);

            if is_root || unreached {
                if chain.len() > 1 && (is_root || !strict) {
                    out.push(chain);
                }
                continue;
            }

            for up in ups.into_iter().flatten() {
                if !visited.insert(*up) {
                    continue;
                }
                let mut next = Vec::with_capacity(chain.len() + 1);
                next.push(*up);
                next.extend_from_slice(&chain);
                queue.push_back(next);
            }
        }
        out
    }
}

/// File offset → virtual address, via the section that contains it. The inverse
/// of the lookup the disassembler uses, needed to turn a string's position in
/// the file into the address code would reference it by.
pub fn off_to_va(bin: &Binary, base: u64, off: u64) -> Option<u64> {
    bin.sections.iter().find_map(|s| {
        (s.file_size > 0 && off >= s.file_off && off < s.file_off + s.file_size)
            .then(|| base + s.vaddr + (off - s.file_off))
    })
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

/// Does this address land in any mapped section?
fn is_mapped(bin: &Binary, base: u64, va: u64) -> bool {
    let Some(rva) = va.checked_sub(base) else {
        return false;
    };
    bin.sections
        .iter()
        .any(|s| s.vaddr != 0 && rva >= s.vaddr && rva < s.vaddr + s.vsize.max(s.file_size))
}

/// The address an instruction *names* without jumping to it: the source of a
/// data cross-reference.
///
/// Two shapes matter. RIP-relative operands (`lea rax, [rip+0x1234]`) are
/// unambiguous and are taken as-is. Bare immediates and absolute displacements
/// are how 32-bit code refers to globals, but they are also just numbers, so
/// they only count when they land somewhere the image actually maps; that
/// filter is what keeps loop counters from being reported as string references.
fn data_ref(bin: &Binary, base: u64, insn: &Instruction) -> Option<u64> {
    if insn.is_ip_rel_memory_operand() {
        let t = insn.ip_rel_memory_address();
        return is_mapped(bin, base, t).then_some(t);
    }

    // Absolute memory operand with no base or index register.
    if insn.memory_base() == iced_x86::Register::None
        && insn.memory_index() == iced_x86::Register::None
    {
        let d = insn.memory_displacement64();
        if d != 0 && is_mapped(bin, base, d) {
            return Some(d);
        }
    }

    // `push offset str` / `mov esi, offset str`: an immediate that happens to
    // be an address. Restricted to non-executable targets, because an immediate
    // pointing into code is far more often arithmetic than a pointer.
    for i in 0..insn.op_count() {
        let v = match insn.op_kind(i) {
            iced_x86::OpKind::Immediate32 => insn.immediate32() as u64,
            iced_x86::OpKind::Immediate64 => insn.immediate64(),
            _ => continue,
        };
        if v != 0 && !in_exec(bin, base, v) && is_mapped(bin, base, v) {
            return Some(v);
        }
    }
    None
}

pub fn analyze(bin: &Binary, bytes: &[u8], max_insns: usize, db: &crate::db::Db) -> Analysis {
    let base = display_base(bin);

    // Forwarding stubs are discovered rather than declared: no symbol table
    // lists them, but they are what call sites actually target.
    let stubs = crate::analysis::thunks::resolve(bin, bytes, base);

    // Names and import slots, keyed by absolute VA.
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    let mut import_slots: BTreeMap<u64, String> = BTreeMap::new();
    let mut imports: BTreeMap<u64, String> = BTreeMap::new();
    for s in bin.symbols.iter().chain(stubs.iter()) {
        let va = s.addr + base;
        match s.kind {
            SymKind::Import => {
                import_slots.insert(va, s.name.clone());
                imports.insert(va, s.name.clone());
            }
            SymKind::Thunk => {
                names.entry(va).or_insert_with(|| s.name.clone());
                imports.insert(va, s.name.clone());
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
    for s in bin.symbols.iter().chain(stubs.iter()) {
        let va = s.addr + base;
        if matches!(s.kind, SymKind::Func | SymKind::Export | SymKind::Thunk)
            && in_exec(bin, base, va)
            && is_seed.insert(va)
        {
            seeds.push_back(va);
        }
    }

    // Your own names win, and they also create work: naming an address the
    // symbol table never mentioned is how you tell the engine there is a
    // function there, which is most of the point of naming something in a
    // stripped binary.
    for (rva, name) in &db.names {
        let va = rva + base;
        names.insert(va, name.clone());
        if in_exec(bin, base, va) && is_seed.insert(va) {
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

    // Overlapping code can be decoded under more than one function, which would
    // otherwise report the same instruction as several distinct references.
    for refs in xrefs_to.values_mut() {
        refs.sort_by_key(|x| (x.from, x.kind as u8));
        refs.dedup_by_key(|x| (x.from, x.kind as u8));
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
        imports,
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
                // `call [rip+disp]` / `jmp [rip+disp]` through an import slot.
                // iced classifies these as *indirect* flow, which is the whole
                // reason they have to be matched separately from the near-branch
                // arms above.
                FlowControl::IndirectCall | FlowControl::IndirectBranch => {
                    let slot = if insn.is_ip_rel_memory_operand() {
                        Some(insn.ip_rel_memory_address())
                    } else if insn.memory_base() == iced_x86::Register::None
                        && insn.memory_index() == iced_x86::Register::None
                        && insn.memory_displacement64() != 0
                    {
                        // 32-bit builds address the IAT absolutely rather than
                        // relative to the instruction pointer.
                        Some(insn.memory_displacement64())
                    } else {
                        None
                    };
                    if let Some(slot) = slot {
                        if let Some(n) = import_slots.get(&slot) {
                            target = Some(slot);
                            target_name = Some(n.clone());
                            // The slot is a call-graph edge like any other, and
                            // without it every path that runs through an import
                            // is invisible. It is never seeded as a function:
                            // an import slot lives in data, and the executable
                            // check below filters it out.
                            calls.push(slot);
                            xrefs_to.entry(slot).or_default().push(Xref {
                                from: addr,
                                kind: if flow == FlowControl::IndirectCall {
                                    XrefKind::Call
                                } else {
                                    XrefKind::Jump
                                },
                            });
                        }
                    }
                }
                _ => {}
            }

            // A data reference is recorded whatever the instruction does with
            // the address, as long as the flow handling above did not already
            // account for it (an import slot is a control-flow edge, not data).
            if target.is_none() {
                if let Some(t) = data_ref(bin, base, &insn) {
                    xrefs_to.entry(t).or_default().push(Xref {
                        from: addr,
                        kind: XrefKind::Data,
                    });
                }
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
            // An indirect branch ends the block just as firmly as a direct one:
            // its successors are unknown, so decoding past it walks into bytes
            // that are not necessarily instructions.
            let stop = matches!(
                flow,
                FlowControl::Return
                    | FlowControl::UnconditionalBranch
                    | FlowControl::IndirectBranch
                    | FlowControl::Interrupt
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

    // Split overlapping blocks. When a branch lands in the middle of a run
    // already decoded, the worklist produces two blocks covering the same
    // instructions: one starting earlier and one at the join point. Trimming
    // each block where the next one begins gives every instruction exactly one
    // home, which is what makes a function listing readable and the block
    // count mean something.
    let starts: Vec<u64> = blocks.keys().copied().collect();
    for (i, start) in starts.iter().enumerate() {
        let Some(&next) = starts.get(i + 1) else {
            continue;
        };
        let Some(b) = blocks.get_mut(start) else {
            continue;
        };
        if b.end > next {
            b.insns.retain(|ins| ins.addr < next);
            b.end = next;
            // Whatever this block used to branch to belongs to the tail that
            // is now the next block; what is left simply falls through.
            b.succ = vec![next];
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::model::{Arch, Section};

    /// A binary that is nothing but one executable section of raw code.
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
        // File offset equals the address, so the padding in front is the
        // simplest way to keep the two in step.
        let mut bytes = vec![0u8; vaddr as usize];
        bytes.extend_from_slice(code);
        (bin, bytes)
    }

    #[test]
    fn a_branch_into_a_decoded_run_does_not_duplicate_instructions() {
        // The conditional at 0x1002 targets 0x1006 and falls through to 0x1004.
        // Decoding from 0x1004 runs straight through 0x1006, so without block
        // splitting the `ret` belongs to two blocks and prints twice.
        let code = [
            0x31, 0xc0, // 0x1000  xor eax, eax
            0x74, 0x02, // 0x1002  je 0x1006
            0x90, // 0x1004  nop
            0x90, // 0x1005  nop
            0xc3, // 0x1006  ret
        ];
        let (bin, bytes) = code_at(0x1000, &code);
        let an = analyze(&bin, &bytes, 1000, &Db::default());
        let f = an.find_function(0x1000).expect("entry recovered");

        let mut seen: Vec<u64> = f
            .blocks
            .iter()
            .flat_map(|b| b.insns.iter().map(|i| i.addr))
            .collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(before, seen.len(), "every instruction belongs to one block");

        // And the blocks tile the range rather than overlapping it.
        let mut spans: Vec<(u64, u64)> = f.blocks.iter().map(|b| (b.start, b.end)).collect();
        spans.sort_unstable();
        for w in spans.windows(2) {
            assert!(
                w[0].1 <= w[1].0,
                "blocks overlap: {:x?} then {:x?}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn a_note_annotates_without_renaming() {
        // Notes are for the reader. Only a name changes what things are called,
        // so a note must leave the entry point's own label alone.
        let code = [0x90, 0xc3]; // nop; ret
        let (bin, bytes) = code_at(0x1000, &code);
        let mut db = Db::default();
        db.set_note(0x1000, "parses the header");
        let an = analyze(&bin, &bytes, 1000, &db);
        assert_eq!(an.label(0x1000), "entry");
    }

    #[test]
    fn a_name_takes_precedence_over_the_derived_label() {
        let code = [0x90, 0xc3];
        let (bin, bytes) = code_at(0x1000, &code);
        let mut db = Db::default();
        db.set_name(0x1000, "parse_header");
        let an = analyze(&bin, &bytes, 1000, &db);
        assert_eq!(an.label(0x1000), "parse_header");
    }
}
