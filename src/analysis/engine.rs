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
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

// Several fields here (instruction length/flow, block end/successors, xref
// kind) are part of the CFG model for the upcoming interactive/graph views and
// are not all read by the current text output yet.
#[allow(dead_code)]
pub struct EngineInsn {
    pub addr: u64,
    pub len: usize,
    /// The instruction's raw bytes. Formatting is deferred to `text`, because
    /// most commands (function lists, sinks, xrefs) never print an operand,
    /// and formatting every instruction of a kernel image only to count it
    /// twice is the kind of waste that shows up as seconds.
    pub bytes: Vec<u8>,
    /// A resolved symbolic target (function name / import), if any.
    pub target_name: Option<String>,
    /// A branch/call target address, if this instruction has one.
    pub target: Option<u64>,
    pub flow: FlowControl,
}

impl EngineInsn {
    /// Render the instruction, formatted on demand from the stored bytes.
    pub fn text(&self, bits: u32, arch: crate::model::Arch) -> String {
        if arch.is_x86() {
            let mut fmt = IntelFormatter::new();
            fmt.options_mut().set_uppercase_hex(false);
            fmt.options_mut().set_hex_prefix("0x");
            fmt.options_mut().set_hex_suffix("");
            fmt.options_mut().set_space_after_operand_separator(true);

            let mut decoder = Decoder::with_ip(bits, &self.bytes, self.addr, DecoderOptions::NONE);
            if !decoder.can_decode() {
                return String::new();
            }
            let insn = decoder.decode();
            let mut s = String::new();
            fmt.format(&insn, &mut s);
            s
        } else {
            crate::analysis::aarch64::text(&self.bytes, self.addr)
        }
    }
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
    /// Virtual addresses of jump tables this function dispatches through.
    pub tables: Vec<u64>,
}

impl Function {
    /// A deterministic fingerprint of the function's raw instruction bytes.
    /// Blocks are visited in address order and every instruction contributes
    /// its address and bytes, so two otherwise-identical functions that differ
    /// by a single edited byte hash differently — `knife diff` uses this to
    /// flag a changed body even when the size lines up.
    pub fn body_hash(&self) -> u64 {
        let mut h = 0x9e37_79b9_7f4a_7c15u64;
        for b in &self.blocks {
            h = h.rotate_left(5) ^ b.start.wrapping_mul(0x8000_0000_0000_0000);
            h ^= b.end;
            for i in &b.insns {
                for byte in &i.bytes {
                    h = h.rotate_left(1) ^ u64::from(*byte);
                }
                h ^= i.addr;
            }
        }
        h
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Xref {
    pub from: u64,
    pub kind: XrefKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    Branch,
    /// An instruction that names an address without transferring control to it:
    /// `lea rax, [rip+str]`, a global load, a function pointer being taken.
    Data,
}

/// A reference *from* an instruction: what it reaches. The mirror of `Xref`,
/// kept because "what does this line point at" is the question the listing and
/// the interactive view ask at every cursor stop.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ref {
    pub to: u64,
    pub kind: XrefKind,
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
    /// The reverse lookup: instruction address -> what it references, whether
    /// that is a call, a branch, or a data operand pointing at a string.
    pub xrefs_from: BTreeMap<u64, Vec<Ref>>,
    pub names: BTreeMap<u64, String>,
    /// Every address that reaches an imported function, whether it is a PLT/ILT
    /// stub or the import slot itself, mapped to its full decorated name. This
    /// is the lookup that turns "where is `strcpy` called" into a set of
    /// addresses to pull cross-references for.
    pub imports: BTreeMap<u64, String>,
    /// Kept for API symmetry; addresses are already absolute, so this is 0.
    pub display_base: u64,
    pub bits: u32,
    pub arch: crate::model::Arch,
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
/// Public because the listing and the interactive view turn addresses back
/// into bytes the same way the disassembler does.
pub fn va_to_off(bin: &Binary, base: u64, va: u64) -> Option<usize> {
    let rva = va.checked_sub(base)?;
    for s in &bin.sections {
        let span = s.vsize.max(s.file_size);
        if s.vaddr != 0 && rva >= s.vaddr && rva < s.vaddr + span {
            let delta = rva - s.vaddr;
            // Only the file-backed part of a section has an offset; an address
            // in the virtual-only tail (a .bss, or a vsize larger than the raw
            // data) has no bytes to point at. Sections are clamped to the file
            // at parse time, so `file_off + delta` here is always in bounds.
            return (delta < s.file_size).then_some((s.file_off + delta) as usize);
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

/// The start address of a jump table if `insn` is an indexed branch into one.
///
/// x86 has no RIP-relative indexed addressing, so a switch works in exactly
/// two shapes, both resolved here:
///
/// * `jmp qword ptr [kind*8 + disp32]` — the displacement is the table's
///   absolute address (non-PIE);
/// * `lea rax, [rip+disp]; jmp qword ptr [rax*8]` — the LEA wrote the table
///   address into `regs`, MSVC's favorite for PIE.
///
/// Anything else (bare `jmp rax`, unindexed memory jumps) has no table.
fn jump_table_base(
    bin: &Binary,
    insn: &iced_x86::Instruction,
    regs: &HashMap<iced_x86::Register, u64>,
) -> Option<u64> {
    if !matches!(
        bin.arch,
        crate::model::Arch::X86 | crate::model::Arch::X86_64
    ) {
        return None;
    }
    let idx = insn.memory_index();
    if idx == iced_x86::Register::None {
        return None;
    }
    let disp = insn.memory_displacement64();
    if let Some(t) = regs.get(&idx) {
        // The base came from an earlier `lea [rip+x]`, with an optional small
        // displacement folded into the addressing (rare but real).
        return Some(t.wrapping_add(disp));
    }
    if insn.memory_base() == iced_x86::Register::None && disp != 0 {
        return Some(disp);
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

    // Container-metadata function starts (the PE exception directory, a
    // prologue sweep). These carry no name, so they seed and bound the descent
    // but leave the function to render as `sub_`. This is what finds the code a
    // stripped C++ binary only ever reaches through indirect calls.
    for rva in &bin.func_hints {
        let va = rva + base;
        if in_exec(bin, base, va) && is_seed.insert(va) {
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
    let mut xrefs_from: BTreeMap<u64, Vec<Ref>> = BTreeMap::new();
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
            &mut xrefs_from,
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
    for refs in xrefs_from.values_mut() {
        refs.sort_by_key(|x| (x.to, x.kind as u8));
        refs.dedup_by_key(|x| (x.to, x.kind as u8));
    }

    let mut incoming: BTreeMap<u64, usize> = BTreeMap::new();
    for (target, refs) in &xrefs_to {
        incoming.insert(*target, refs.len());
    }
    for f in &mut functions {
        f.incoming = incoming.get(&f.addr).copied().unwrap_or(0);
        f.named = names.contains_key(&f.addr);
        if !f.named {
            // A nameless function whose opening bytes match a known helper
            // gets the helper's name instead of a flow-graph serial number.
            if let Some(off) = va_to_off(bin, base, f.addr) {
                if let Some(sig) = crate::analysis::flirt::identify(bytes, off, f.size as usize) {
                    names.insert(f.addr, sig.to_string());
                    f.name = sig.to_string();
                    f.named = true;
                }
            }
        }
        if !f.named {
            f.name = format!("sub_{:x}", f.addr);
        }
    }
    functions.sort_by_key(|f| f.addr);

    Analysis {
        functions,
        xrefs_to,
        xrefs_from,
        names,
        imports,
        display_base: 0,
        bits: bin.bits,
        arch: bin.arch,
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
    xrefs_from: &mut BTreeMap<u64, Vec<Ref>>,
    budget: usize,
) -> (Function, Vec<u64>, usize) {
    let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
    let mut worklist: VecDeque<u64> = VecDeque::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut calls: Vec<u64> = Vec::new();
    let mut tables: Vec<u64> = Vec::new();
    let mut spent = 0usize;
    let mut min_start = entry;
    let mut max_end = entry;
    // Addresses the code is known to have written into registers (only ever
    // via `lea r64,[rip+x]` / `mov r64, imm`), which is what makes a switch's
    // table address knowable. Inaccurate across conditional paths by design —
    // a stale entry can only *miss* a table, never invent one.
    let mut regs: HashMap<iced_x86::Register, u64> = HashMap::new();

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
        // A corrupted section header can map a valid-looking address to an
        // offset past the end of the file; the bounds check keeps that from
        // becoming a crash on a hostile binary.
        let Some(code) = bytes.get(off..) else {
            continue;
        };
        min_start = min_start.min(block_start);
        let mut decoder = Decoder::with_ip(bin.bits, code, block_start, DecoderOptions::NONE);
        // AArch64 has no variable-width decoding: the cursor is just +4 each
        // instruction.
        let mut apos = 0usize;
        let is_a64 = bin.arch == crate::model::Arch::Aarch64;
        let mut insns = Vec::new();
        let mut succ = Vec::new();
        let mut end = block_start;

        loop {
            if spent >= budget {
                break;
            }
            // One decoded instruction, normalized to what the flow handling
            // needs, plus the iced view for the x86-only bits (IAT slots,
            // jump tables, register tracking).
            let mut ice: Option<Instruction> = None;
            let (addr, len, raw, flow, dtarget) = if is_a64 {
                let at = block_start + apos as u64;
                let Some(chunk) = bytes.get(off + apos..) else {
                    break;
                };
                let Some(w) = crate::analysis::aarch64::decode(chunk, at) else {
                    break;
                };
                spent += 1;
                let raw = chunk[..w.len].to_vec();
                apos += w.len;
                (w.addr, w.len, raw, w.flow, w.target)
            } else {
                if !decoder.can_decode() {
                    break;
                }
                let pos = decoder.position();
                let insn = decoder.decode();
                if insn.is_invalid() {
                    break;
                }
                spent += 1;
                let flow = insn.flow_control();
                let dtarget = if matches!(
                    flow,
                    FlowControl::Call
                        | FlowControl::UnconditionalBranch
                        | FlowControl::ConditionalBranch
                ) && matches!(
                    insn.op0_kind(),
                    iced_x86::OpKind::NearBranch16
                        | iced_x86::OpKind::NearBranch32
                        | iced_x86::OpKind::NearBranch64
                ) {
                    Some(insn.near_branch_target())
                } else {
                    None
                };
                let addr = insn.ip();
                let len = insn.len();
                let raw = bytes[off + pos..off + pos + len].to_vec();
                ice = Some(insn);
                (addr, len, raw, flow, dtarget)
            };
            end = addr + len as u64;
            max_end = max_end.max(end);
            let mut target = dtarget;
            let mut target_name = None;

            // Constant register tracking (see `regs`), general-case limited to
            // the two shapes real compilers use to address switch tables.
            if let Some(insn) = &ice {
                if insn.op0_kind() == iced_x86::OpKind::Register {
                    let reg = insn.op0_register();
                    let known = if insn.mnemonic() == iced_x86::Mnemonic::Lea
                        && insn.is_ip_rel_memory_operand()
                    {
                        let t = insn.ip_rel_memory_address();
                        is_mapped(bin, base, t).then_some(t)
                    } else if insn.mnemonic() == iced_x86::Mnemonic::Mov
                        && insn.op_count() == 2
                        && insn.op1_kind() == iced_x86::OpKind::Immediate64
                    {
                        let t = insn.immediate64();
                        is_mapped(bin, base, t).then_some(t)
                    } else {
                        None
                    };
                    if let Some(t) = known {
                        regs.insert(reg, t);
                    }
                }
            }

            match flow {
                FlowControl::Call => {
                    if let Some(t) = target {
                        target_name = names.get(&t).cloned();
                        calls.push(t);
                        xrefs_to.entry(t).or_default().push(Xref {
                            from: addr,
                            kind: XrefKind::Call,
                        });
                        xrefs_from.entry(addr).or_default().push(Ref {
                            to: t,
                            kind: XrefKind::Call,
                        });
                    }
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(t) = target {
                        target_name = names.get(&t).cloned();
                        let kind = XrefKind::Jump;
                        xrefs_to
                            .entry(t)
                            .or_default()
                            .push(Xref { from: addr, kind });
                        xrefs_from
                            .entry(addr)
                            .or_default()
                            .push(Ref { to: t, kind });
                        // tail-call to another function, or an intra-function
                        // jump?
                        if boundaries.contains(&t) && t != entry {
                            calls.push(t); // treat as a tail call
                        } else if queue_block(t, &mut seen, &mut worklist) {
                            succ.push(t);
                        }
                    }
                }
                FlowControl::ConditionalBranch => {
                    if let Some(t) = target {
                        target_name = names.get(&t).cloned();
                        xrefs_to.entry(t).or_default().push(Xref {
                            from: addr,
                            kind: XrefKind::Branch,
                        });
                        xrefs_from.entry(addr).or_default().push(Ref {
                            to: t,
                            kind: XrefKind::Branch,
                        });
                        if queue_block(t, &mut seen, &mut worklist) {
                            succ.push(t);
                        }
                    }
                }
                // `call [rip+disp]` / `jmp [rip+disp]` through an import slot.
                // iced classifies these as *indirect* flow, which is the whole
                // reason they have to be matched separately from the near-branch
                // arms above.
                FlowControl::IndirectCall | FlowControl::IndirectBranch => {
                    // AArch64 register branches (br/blr) have the same flow
                    // class but nothing resolvable here; the x86 slot and
                    // table machinery needs the iced view, which is absent.
                    if let Some(insn) = &ice {
                        let slot = if insn.is_ip_rel_memory_operand() {
                            Some(insn.ip_rel_memory_address())
                        } else if insn.memory_base() == iced_x86::Register::None
                            && insn.memory_index() == iced_x86::Register::None
                            && insn.memory_displacement64() != 0
                        {
                            // 32-bit builds address the IAT absolutely rather
                            // than relative to the instruction pointer.
                            Some(insn.memory_displacement64())
                        } else {
                            None
                        };
                        if let Some(slot) = slot {
                            if let Some(n) = import_slots.get(&slot) {
                                target = Some(slot);
                                target_name = Some(n.clone());
                                // The slot is a call-graph edge like any other,
                                // and without it every path that runs through
                                // an import is invisible. It is never seeded
                                // as a function: an import slot lives in data,
                                // and the executable check below filters it.
                                calls.push(slot);
                                let kind = if flow == FlowControl::IndirectCall {
                                    XrefKind::Call
                                } else {
                                    XrefKind::Jump
                                };
                                xrefs_to
                                    .entry(slot)
                                    .or_default()
                                    .push(Xref { from: addr, kind });
                                xrefs_from
                                    .entry(addr)
                                    .or_default()
                                    .push(Ref { to: slot, kind });
                            }
                        }
                        // An indexed branch that no import slot explains is a
                        // switch: `jmp [table + i*8]`. The table entries are
                        // real control-flow edges, and without them the cases
                        // look unreachable.
                        if target.is_none() && flow == FlowControl::IndirectBranch {
                            if let Some(table) = jump_table_base(bin, insn, &regs) {
                                let width = if bin.bits == 64 { 8usize } else { 4 };
                                let mut at = table;
                                for read in 0..4096usize {
                                    let Some(off) = va_to_off(bin, base, at) else {
                                        break;
                                    };
                                    let Some(e) = bytes.get(off..off + width) else {
                                        break;
                                    };
                                    let t = if bin.bits == 64 {
                                        u64::from_le_bytes(e.try_into().unwrap())
                                    } else {
                                        u32::from_le_bytes(e.try_into().unwrap()) as u64
                                    };
                                    if t == 0 || !in_exec(bin, base, t) {
                                        break;
                                    }
                                    if read == 0 {
                                        tables.push(table);
                                    }
                                    xrefs_to.entry(t).or_default().push(Xref {
                                        from: addr,
                                        kind: XrefKind::Jump,
                                    });
                                    xrefs_from.entry(addr).or_default().push(Ref {
                                        to: t,
                                        kind: XrefKind::Jump,
                                    });
                                    if queue_block(t, &mut seen, &mut worklist) {
                                        succ.push(t);
                                    }
                                    at += width as u64;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }

            // A data reference is recorded whatever the instruction does with
            // the address, as long as the flow handling above did not already
            // account for it (an import slot is a control-flow edge, not data).
            if target.is_none() {
                if let Some(insn) = &ice {
                    if let Some(t) = data_ref(bin, base, insn) {
                        xrefs_to.entry(t).or_default().push(Xref {
                            from: addr,
                            kind: XrefKind::Data,
                        });
                        xrefs_from.entry(addr).or_default().push(Ref {
                            to: t,
                            kind: XrefKind::Data,
                        });
                    }
                }
            }

            insns.push(EngineInsn {
                addr,
                len,
                bytes: raw,
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
            // If the next instruction begins a block we already know about, this
            // block falls through into it. Stop here and record the edge rather
            // than decoding the shared tail again: without this, a run with many
            // branch targets gets re-decoded once per target, which turns a
            // dense function into near-quadratic work and silently exhausts the
            // instruction budget on real binaries.
            if end != block_start && seen.contains(&end) {
                succ.push(end);
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
            ) || ice
                .as_ref()
                .is_some_and(|i| i.mnemonic() == Mnemonic::Int3)
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
        tables,
    };
    (func, discovered, spent)
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
    fn a_func_hint_recovers_code_no_control_flow_reaches() {
        // Two functions back to back. The entry (0x1000) just returns; the
        // second (0x1002) is never called from anywhere the engine can see, so
        // recursive descent alone never finds it. A func_hint is the only way
        // in, which is the whole point of the PE exception directory.
        let code = [
            0xc3, // 0x1000  ret         (entry)
            0x90, // 0x1001  padding
            0x31, 0xc0, // 0x1002  xor eax, eax  (second function)
            0xc3, // 0x1004  ret
        ];
        let (mut bin, bytes) = code_at(0x1000, &code);

        // Without a hint, only the entry is recovered.
        let bare = analyze(&bin, &bytes, 1000, &Db::default());
        assert!(bare.find_function(0x1002).is_none());

        // With the hint, the second function appears.
        bin.func_hints = vec![0x1002];
        let with_hint = analyze(&bin, &bytes, 1000, &Db::default());
        let f = with_hint
            .find_function(0x1002)
            .expect("the hinted function should be recovered");
        assert!(!f.blocks.is_empty());
        // It has no name, so it renders as sub_ like any discovered function.
        assert_eq!(with_hint.label(0x1002), "sub_1002");
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
    fn a_signature_match_names_the_function() {
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, // 0x1000  call 0x1005 (the helper)
            0x48, 0x8b, 0x05, 0x12, 0x34, 0x56, 0x78, 0x48, 0x3b, 0x04, 0x24, 0x75, 0x02, 0xf3,
            0xc3, // 0x1005  the cookie check itself
            0xc3, // 0x1014  trailing ret
        ];
        let (bin, bytes) = code_at(0x1000, &code);
        let an = analyze(&bin, &bytes, 1000, &Db::default());
        let helper = an
            .functions
            .iter()
            .find(|f| f.addr == 0x1005)
            .expect("helper recovered");
        assert!(helper.named);
        assert_eq!(helper.name, "__security_check_cookie");
    }

    #[test]
    fn a_jump_table_brings_the_cases_in() {
        // MSVC PIE switch shape:
        //   0x4000: lea rax, [rip+0xff9]        -> rax = 0x5000 (the table)
        //   0x4007: jmp qword ptr [rax*8 + 0]   (ff 24 c5 00 00 00 00)
        // table at 0x5000: 0x6000, 0x6007, 0x600e, 0 (all code, zero ends)
        let mut code = vec![0u8; 0x5018];
        code[0x0000] = 0x48; // lea rax, [rip + 0xff9]   (0x4007 -> 0x5000)
        code[0x0001] = 0x8d;
        code[0x0002] = 0x05;
        code[0x0003..0x0007].copy_from_slice(&0xff9i32.to_le_bytes());
        code[0x0007] = 0xff; // jmp qword ptr [rax*8 + 0]
        code[0x0008] = 0x24;
        code[0x0009] = 0xc5;
        // table
        code[0x1000..0x1008].copy_from_slice(&0x6000u64.to_le_bytes());
        code[0x1008..0x1010].copy_from_slice(&0x6007u64.to_le_bytes());
        code[0x1010..0x1018].copy_from_slice(&0x600eu64.to_le_bytes());
        // cases
        code[0x2000] = 0xc3;
        code[0x2007] = 0xc3;
        code[0x200e] = 0xc3;

        let (bin, bytes) = code_at(0x4000, &code);
        let an = analyze(&bin, &bytes, 10_000, &Db::default());
        let sw = an.find_function(0x4000).expect("entry recovered");
        assert_eq!(sw.tables, vec![0x5000], "the table is attributed");
        for case in [0x6000u64, 0x6007, 0x600e] {
            assert!(
                an.xrefs_from.get(&0x4007).is_some_and(|r| r
                    .iter()
                    .any(|x| x.to == case && matches!(x.kind, XrefKind::Jump))),
                "case {case:#x} reachable from the dispatch"
            );
        }
        // the cases were decoded as real code: they are blocks of the switch
        // function, not dangling pointers that never got decoded
        for case in [0x6000u64, 0x6007, 0x600e] {
            assert!(
                sw.blocks.iter().any(|b| b.start == case),
                "case {case:#x} became a block"
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

    #[test]
    fn xrefs_from_mirrors_the_call_edges() {
        // entry calls sub at 0x1006, both return.
        let code = [
            0xe8, 0x01, 0x00, 0x00, 0x00, // 0x1000 call 0x1006
            0xc3, // 0x1005 ret
            0xc3, // 0x1006 ret
        ];
        let (bin, bytes) = code_at(0x1000, &code);
        let an = analyze(&bin, &bytes, 1000, &Db::default());
        let refs = an.xrefs_from.get(&0x1000).expect("call recorded");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to, 0x1006);
        assert_eq!(refs[0].kind, XrefKind::Call);
        // and the reverse index agrees with the forward one.
        assert!(an.xrefs_to.get(&0x1006).is_some_and(|r| r
            .iter()
            .any(|x| x.from == 0x1000 && x.kind == XrefKind::Call)));
    }

    #[test]
    fn xrefs_from_records_a_string_operand() {
        // lea rax, [rip+0x17] at 0x1000 ends at 0x1007, so it names 0x101e,
        // which is where the literal sits in the read-only section.
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
        let an = analyze(&bin, &bytes, 1000, &Db::default());
        let refs = an.xrefs_from.get(&0x1000).expect("operand recorded");
        assert!(refs
            .iter()
            .any(|r| r.to == 0x101e && r.kind == XrefKind::Data));
    }

    #[test]
    fn the_aarch64_fixture_flows_without_x86() {
        let bytes = crate::formats::fixture::elf_aarch64_call();
        let bin = crate::formats::analyze("stub", &bytes).expect("parses");
        assert_eq!(bin.arch, Arch::Aarch64);

        let an = analyze(&bin, &bytes, 1000, &Db::default());
        let entry = an.find_function(bin.entry).expect("entry recovered");
        assert!(entry.blocks.iter().any(|b| b.start == bin.entry));
        // the `bl` resolved to an internal helper, with the xref recorded
        let helper = bin.entry + 0x10;
        assert!(
            an.xrefs_from.get(&bin.entry).is_some_and(|rs| rs
                .iter()
                .any(|r| r.to == helper && r.kind == XrefKind::Call)),
            "call edge into the helper"
        );
        let h = an.find_function(helper).expect("helper recovered");
        assert_eq!(h.blocks.len(), 1);
        assert_eq!(h.blocks[0].insns.len(), 3);

        // formatting comes from the A64 renderer, not iced's x86 decoder
        let insns = &entry.blocks[0].insns;
        assert!(
            insns[0].text(bin.bits, bin.arch).starts_with("bl"),
            "{}",
            insns[0].text(bin.bits, bin.arch)
        );
        assert_eq!(h.blocks[0].insns[2].text(bin.bits, bin.arch), "ret");
    }

    #[test]
    fn the_aarch64_linear_disassembler_names_the_common_forms() {
        let bytes = crate::formats::fixture::elf_aarch64_call();
        let bin = crate::formats::analyze("stub", &bytes).unwrap();
        let insns = crate::analysis::disasm::disassemble(
            &bytes, bin.entry, bin.entry, bin.bits, bin.arch, 8,
        );
        let texts: Vec<&str> = insns.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(texts.len(), 8, "{texts:?}");
        assert!(texts[0].starts_with("bl"), "{texts:?}");
        assert_eq!(texts[1], "movz    x0, #0x2a", "{texts:?}");
        assert_eq!(texts[2], "ret", "{texts:?}");
        assert_eq!(texts[3], "nop", "{texts:?}");
        assert_eq!(texts[4], "add     x0, x1, x2", "{texts:?}");
        assert_eq!(texts[5], "ldr     x1, [x0, #0]", "{texts:?}");
        assert_eq!(texts[6], "ret", "{texts:?}");
        assert!(texts[7].starts_with("dword"), "{texts:?}");
    }
}
