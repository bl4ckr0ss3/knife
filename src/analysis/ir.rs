//! The decompiler engine: an intermediate representation and the passes that
//! turn a lifted instruction stream into something that reads like C.
//!
//! The disassembler already hands us basic blocks and a control-flow graph. The
//! engine lifts each instruction into a small typed IR, then runs passes over
//! it: expression propagation folds a run of `mov`/`lea`/`add` into the single
//! expression it computes, liveness-driven dead-store elimination drops the
//! intermediate assignments that propagation made redundant, and constant
//! folding tidies the arithmetic. What survives is one statement per thing the
//! code actually does.
//!
//! Control flow is then structured: dominators and post-dominators drive a
//! recursive emitter that reconstructs `if`/`else` and `while` from the graph.
//! The reducible skeleton reads as nested C; the few edges that break nesting
//! (shared `switch` tails, a jump into a common handler) become an explicit
//! `goto` to a labelled block, so the flow is preserved exactly rather than
//! approximated. It is still not a full decompiler: type recovery is deliberately
//! conservative and currently limited to ABI parameters, returns, literals, and
//! known library prototypes.
//! The honest rule holds throughout: an instruction the lifter does not model
//! becomes an opaque `asm(...)` statement, never a guess.

use crate::analysis::engine::{Analysis, Function};
use crate::analysis::strings::Located;
use crate::db::Db;
use crate::model::{Binary, Format};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, InstructionInfoFactory, IntelFormatter,
    MemorySizeOptions, Mnemonic, OpAccess, OpKind, Register,
};
use std::collections::{BTreeMap, BTreeSet};

/// What the renderer needs to turn addresses into names: the analysis (for
/// symbols and imports) and the string literals (so a pointer into one reads as
/// the quoted text). Passed by value; it is two references.
#[derive(Clone, Copy)]
struct Rx<'a> {
    an: &'a Analysis,
    strings: &'a BTreeMap<u64, Located>,
    db: &'a Db,
    /// Base-relative function entry used to scope type bindings.
    function: u64,
}

/// A short, escaped, quoted rendering of a string literal.
fn quote(s: &str) -> String {
    let shown: String = s.chars().take(32).collect();
    let esc = shown
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    if s.chars().count() > 32 {
        format!("\"{esc}\"...")
    } else {
        format!("\"{esc}\"")
    }
}

// ── IR ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Const(u64),
    /// A register, held by its 64-bit root, remembering the width actually used
    /// so the rendering stays faithful (`eax` vs `rax`).
    Reg(Register, Register),
    /// A memory access `*(addr)`.
    Mem(Box<Expr>),
    /// The address of a memory operand: `&(...)`, from `lea`.
    Addr(Box<Expr>),
    /// A frame slot, identified by its signed offset from the frame pointer:
    /// negative is a local (`var_28`), positive an argument (`arg_8`). Wrapped
    /// in `Mem` it is the slot's value; wrapped in `Addr` it is its address.
    Stack(i64),
    /// A global at a fixed address (an absolute or RIP-relative memory operand),
    /// rendered by its symbol name if known and `g_<addr>` otherwise. Like
    /// `Stack`, it is an address: `Mem` reads the global, `Addr` takes its address.
    Global(u64),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    /// A unary operation on one value: `-x` from `neg`, `~x` from `not`.
    Un(&'static str, Box<Expr>),
    /// A value selected by control flow at a CFG join. Inputs are deduplicated
    /// and ordered by predecessor block, making the IR deterministic.
    ///
    /// The register carries which value this is, so a join that cannot be turned
    /// into a conditional still has something true to say. `phi` is a word about
    /// how the analysis works, not about the program; printing it puts a term
    /// from the middle of the compiler in front of someone reading C.
    Phi(Register, Vec<Expr>),
    /// A conditional value `cond ? a : b`, from a `cmov`.
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    /// A resolved (or register-indirect) call with its recovered arguments.
    Call(String, Vec<Expr>),
    /// Something the lifter chose not to model as a value.
    Opaque(String),
}

#[derive(Debug, Clone)]
pub enum Stmt {
    /// `dst = src`. `dst` is a `Reg` or a `Mem`.
    Set(Expr, Expr),
    /// A call whose return value is unused.
    CallVoid(Expr),
    Ret(Option<Expr>),
    /// Conditional branch to a label address.
    Branch(Expr, u64),
    Goto(u64),
    /// An indexed indirect jump (a jump table). The expression is the selector;
    /// the case targets are the block's successors, resolved by the engine.
    Switch(Expr),
    /// Verbatim assembly for an unmodelled instruction, with what it touches.
    ///
    /// The registers matter as much as the text. An unmodelled instruction is
    /// still an instruction: it writes registers, and every pass downstream has
    /// to know that or it will reason about values the machine has already
    /// replaced. `div` is unmodelled and writes `rax`; without `defs` the
    /// propagator happily carries the old `rax` past it and prints a value that
    /// was never there. Without `uses`, the store feeding it looks dead and is
    /// deleted. Being unable to describe an instruction is fine; pretending it
    /// did nothing is not.
    Asm {
        text: String,
        defs: Vec<Register>,
        uses: Vec<Register>,
    },
}

/// A block of lifted statements with its address and successors.
struct IrBlock {
    start: u64,
    stmts: Vec<Stmt>,
    succ: Vec<u64>,
}

/// One rendered output line.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Line {
    pub label: bool,
    pub text: String,
}

// ── entry point ───────────────────────────────────────────────────────────

/// Decompile a recovered function to pseudocode lines. `strings` lets a pointer
/// into a literal render as the quoted text.
pub fn decompile(
    an: &Analysis,
    bin: &Binary,
    f: &Function,
    strings: &BTreeMap<u64, Located>,
    db: &Db,
) -> Vec<Line> {
    // Everything below decodes with `iced_x86`, whatever the target is. On an
    // AArch64 image that reads four-byte ARM words as x86: most fail to decode
    // and vanish, and the few that happen to form a valid x86 instruction are
    // lifted as one. The result is not a rougher answer, it is an invented one —
    // statements about `rax` on a machine with no `rax` — and it arrived with no
    // warning at all. Say so instead, here rather than in each caller, so the
    // terminal, the window and the agents all get the same honest reply.
    if !crate::analysis::disasm::lifting_supported(an.arch) {
        return vec![Line {
            label: false,
            text: format!(
                "/* pseudocode is x86/x64 only; this image is {}.                  `knife dis` disassembles it. */",
                an.arch.label()
            ),
        }];
    }
    let win64 = bin.format == Format::Pe && an.bits == 64;
    let frame = has_frame_pointer(an, f);

    // Predecessor and successor indices, so propagation can follow the CFG
    // rather than address order.
    let n = f.blocks.len();
    let idx: BTreeMap<u64, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start, i))
        .collect();
    let mut preds: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, b) in f.blocks.iter().enumerate() {
        for s in &b.succ {
            if let Some(&j) = idx.get(s) {
                preds[j].insert(i);
                succ[i].push(j);
            }
        }
    }

    // Lift each block from the meet of its predecessors' exit states, iterating
    // to a fixpoint in reverse postorder so forward edges and back edges also
    // converge. The meet is the SSA merge rule: a register keeps its propagated
    // value only when every incoming path agrees on the same expression, so a
    // value defined on both arms of an if/else survives the join, while one
    // that differs on some path is dropped (conservative, never a guess).
    let rpo = reverse_postorder(&succ, 0);
    let idom = dominators(&succ, 0);
    let mut entry: Vec<BTreeMap<Register, Expr>> = vec![BTreeMap::new(); n];
    let mut exit: Vec<BTreeMap<Register, Expr>> = vec![BTreeMap::new(); n];
    // The recovered comparison is carried the same way, so a `cmp` shared by
    // conditional jumps in several blocks reaches each `jcc` that reads it.
    let mut entry_cmp: Vec<Option<Cmp>> = vec![None; n];
    let mut exit_cmp: Vec<Option<Cmp>> = vec![None; n];
    // The stack pointer's position is carried the same way, so a local addressed
    // in the body resolves to the right slot even after the prologue moved rsp.
    let mut entry_stk: Vec<StackSt> = vec![StackSt::default(); n];
    let mut exit_stk: Vec<StackSt> = vec![StackSt::default(); n];
    let mut lifted = vec![false; n];
    let mut blocks: Vec<IrBlock> = Vec::with_capacity(n);
    for b in &f.blocks {
        blocks.push(IrBlock {
            start: b.start,
            stmts: Vec::new(),
            succ: b.succ.clone(),
        });
    }
    let mut changed = true;
    // The meet only ever drops or coarsens values, so the lattice descends and
    // the fixpoint terminates; the cap is a guard against a pathological graph.
    let mut guard = 0;
    while changed && guard <= n + 1 {
        changed = false;
        guard += 1;
        for &i in &rpo {
            // Expression-valued phi nodes converge for acyclic joins. Loop
            // headers need stable SSA value IDs; until that pass exists, keep
            // their merge conservative instead of recursively nesting phis.
            let is_loop_header = preds[i].iter().any(|&p| dominates(i, p, &idom));
            let meet = meet_states(&preds[i], &exit, !is_loop_header);
            let meet_c = meet_cmp(&preds[i], &exit_cmp);
            let meet_s = meet_stack(&preds[i], &exit_stk);
            let entry_changed =
                meet != entry[i] || meet_c != entry_cmp[i] || meet_s != entry_stk[i];
            entry[i] = meet;
            entry_cmp[i] = meet_c;
            entry_stk[i] = meet_s;
            if entry_changed || !lifted[i] {
                lifted[i] = true;
                let (stmts, exit_state, exit_c, exit_s) = lift_block(
                    &f.blocks[i],
                    an,
                    bin,
                    win64,
                    frame,
                    entry[i].clone(),
                    entry_cmp[i].clone(),
                    entry_stk[i].clone(),
                    db,
                );
                blocks[i].stmts = stmts;
                if exit_state != exit[i] || exit_c != exit_cmp[i] || exit_s != exit_stk[i] {
                    exit[i] = exit_state;
                    exit_cmp[i] = exit_c;
                    exit_stk[i] = exit_s;
                    changed = true;
                }
            }
        }
    }

    // A two-arm acyclic phi with a provable controlling branch is ordinary C's
    // conditional operator. Lower only direct diamonds; complex joins keep an
    // explicit `phi(...)` so the output never invents a condition.
    lower_diamond_phis(&mut blocks, &preds, &succ, &idx);

    // Propagation happens during lifting (so a call snapshots each argument's
    // value at its push, not the register's final value). The passes left are
    // dead-store elimination, which needs whole-function liveness so a value
    // used only in a later block survives, and constant folding.
    dead_store_elim(&mut blocks);
    for b in &mut blocks {
        for s in &mut b.stmts {
            fold_stmt(s);
        }
    }

    // Structure the control flow into nested if/else and while, with a goto for
    // the few edges that break nesting. The flat rendering is the fallback for a
    // graph structuring cannot accept at all (an unreachable or empty block).
    structure(an, bin, f, &blocks, strings, db)
        .unwrap_or_else(|| render(an, bin, f, &blocks, strings, db))
}

fn lower_diamond_phis(
    blocks: &mut [IrBlock],
    preds: &[BTreeSet<usize>],
    succ: &[Vec<usize>],
    index: &BTreeMap<u64, usize>,
) {
    for join in 0..blocks.len() {
        let incoming: Vec<usize> = preds[join].iter().copied().collect();
        if incoming.len() != 2 {
            continue;
        }
        let Some(control) = succ.iter().position(|edges| {
            edges.len() == 2 && edges.contains(&incoming[0]) && edges.contains(&incoming[1])
        }) else {
            continue;
        };
        let Some((condition, target)) = blocks[control].stmts.iter().rev().find_map(|stmt| {
            if let Stmt::Branch(condition, target) = stmt {
                Some((condition.clone(), *target))
            } else {
                None
            }
        }) else {
            continue;
        };
        let Some(&taken) = index.get(&target) else {
            continue;
        };
        if !incoming.contains(&taken) {
            continue;
        }
        let taken_pos = usize::from(incoming[1] == taken);
        for statement in &mut blocks[join].stmts {
            rewrite_stmt_phis(statement, &condition, taken_pos);
        }
    }
}

fn rewrite_stmt_phis(statement: &mut Stmt, condition: &Expr, taken_pos: usize) {
    match statement {
        Stmt::Set(dst, src) => {
            rewrite_expr_phis(dst, condition, taken_pos);
            rewrite_expr_phis(src, condition, taken_pos);
        }
        Stmt::CallVoid(expr)
        | Stmt::Ret(Some(expr))
        | Stmt::Branch(expr, _)
        | Stmt::Switch(expr) => rewrite_expr_phis(expr, condition, taken_pos),
        Stmt::Ret(None) | Stmt::Goto(_) | Stmt::Asm { .. } => {}
    }
}

fn rewrite_expr_phis(expr: &mut Expr, condition: &Expr, taken_pos: usize) {
    match expr {
        Expr::Phi(_, values) if values.len() == 2 => {
            let fall_pos = 1 - taken_pos;
            *expr = Expr::Ternary(
                Box::new(condition.clone()),
                Box::new(values[taken_pos].clone()),
                Box::new(values[fall_pos].clone()),
            );
        }
        Expr::Mem(inner) | Expr::Addr(inner) | Expr::Un(_, inner) => {
            rewrite_expr_phis(inner, condition, taken_pos)
        }
        Expr::Bin(_, left, right) => {
            rewrite_expr_phis(left, condition, taken_pos);
            rewrite_expr_phis(right, condition, taken_pos);
        }
        Expr::Phi(_, values) => values
            .iter_mut()
            .for_each(|value| rewrite_expr_phis(value, condition, taken_pos)),
        Expr::Ternary(cond, yes, no) => {
            rewrite_expr_phis(cond, condition, taken_pos);
            rewrite_expr_phis(yes, condition, taken_pos);
            rewrite_expr_phis(no, condition, taken_pos);
        }
        Expr::Call(_, args) => args
            .iter_mut()
            .for_each(|arg| rewrite_expr_phis(arg, condition, taken_pos)),
        Expr::Const(_) | Expr::Reg(..) | Expr::Stack(_) | Expr::Global(_) | Expr::Opaque(_) => {}
    }
}

/// The SSA merge rule for propagation state: a register keeps its value only
/// when every incoming edge carries the same expression. With no predecessors
/// (the entry block) or a single predecessor, the state is taken directly; at a
/// join, a register that differs on any path is dropped rather than guessed.
fn meet_states(
    preds: &BTreeSet<usize>,
    exit: &[BTreeMap<Register, Expr>],
    allow_phi: bool,
) -> BTreeMap<Register, Expr> {
    let mut it = preds.iter();
    let Some(&first) = it.next() else {
        return BTreeMap::new();
    };
    let rest: Vec<usize> = it.copied().collect();
    let mut out = BTreeMap::new();
    for (&register, first_value) in &exit[first] {
        let mut values = vec![first_value.clone()];
        let mut complete = true;
        for &p in &rest {
            let Some(value) = exit[p].get(&register) else {
                complete = false;
                break;
            };
            if !values.contains(value) {
                values.push(value.clone());
            }
        }
        if complete && (values.len() == 1 || allow_phi) {
            let value = if values.len() == 1 {
                values.pop().expect("one merged value")
            } else {
                Expr::Phi(register, values)
            };
            out.insert(register, value);
        }
    }
    out
}

/// The same merge rule for the recovered comparison: it reaches a block only
/// when every predecessor leaves the identical comparison. Any disagreement (or
/// a block whose flags were clobbered) drops it, so a branch never reads a
/// comparison that does not hold on all paths into it.
fn meet_cmp(preds: &BTreeSet<usize>, exit_cmp: &[Option<Cmp>]) -> Option<Cmp> {
    let mut it = preds.iter();
    let first = exit_cmp[*it.next()?].clone();
    for &p in it {
        if exit_cmp[p] != first {
            return None;
        }
    }
    first
}

/// Where the stack pointer stands, tracked so a function without a frame pointer
/// (the common x64 case) still gets named locals. `sp` is `rsp`'s offset from
/// the value it had at function entry (0 = the return address); `alias` records
/// the registers that hold a copy of the stack pointer, such as the `rax` in
/// MSVC's `mov rax, rsp` prologue. `None` for `sp` means "unknown here", so a
/// stack access simply is not named rather than named wrongly.
#[derive(Clone, PartialEq, Default)]
struct StackSt {
    sp: Option<i64>,
    alias: BTreeMap<Register, i64>,
}

impl StackSt {
    fn at_entry() -> Self {
        StackSt {
            sp: Some(0),
            alias: BTreeMap::new(),
        }
    }
}

/// Merge the stack state across a join: `sp` survives only when every
/// predecessor agrees, and an alias only when every predecessor holds it at the
/// same offset. A block with no predecessors is the entry, where `rsp` is 0.
fn meet_stack(preds: &BTreeSet<usize>, exit: &[StackSt]) -> StackSt {
    let mut it = preds.iter();
    let Some(&first) = it.next() else {
        return StackSt::at_entry();
    };
    let mut out = exit[first].clone();
    for &p in it {
        let o = &exit[p];
        if out.sp != o.sp {
            out.sp = None;
        }
        out.alias.retain(|k, v| o.alias.get(k) == Some(v));
    }
    out
}

// ── lifting ─────────────────────────────────────────────────────────────────

fn decode(raw: &[u8], ip: u64, bits: u32) -> Option<Instruction> {
    if raw.is_empty() {
        return None;
    }
    let mut d = Decoder::with_ip(bits, raw, ip, DecoderOptions::NONE);
    d.can_decode()
        .then(|| d.decode())
        .filter(|i| !i.is_invalid())
}

/// State carried while lifting a single block. The register map is the
/// propagation state: an operand read substitutes the expression a register
/// currently holds, so each `push` snapshots its argument's value at that point
/// rather than the register's final value.
/// How the flags a conditional jump will read were set. `Compare` is an explicit
/// `cmp a, b`, so the condition is `a <op> b`; `Zero` and its friends are a
/// `test` or a flag-setting arithmetic op (`dec`, `sub`, `and`, ...), whose
/// result is compared against zero — `ZeroClearsCf` and `NegResult` additionally
/// pin down the carry flag, which `sbb` reads. `Bit` is a `bt`/`bts`/`btr`
/// reading one bit into the carry flag; the recorded left side is
/// `(value >> index) & 1`.
#[derive(Clone, Copy, PartialEq)]
enum FlagSrc {
    Compare,
    Zero,
    /// A `test`/`and`/`or`/`xor`: the carry flag is cleared, defined.
    ZeroClearsCf,
    /// A `neg`: the carry flag is set iff the operand was non-zero, which is
    /// exactly the recorded result being non-zero.
    NegResult,
    Bit,
}

#[derive(Default)]
struct Lift {
    regs: BTreeMap<Register, Expr>,
    /// Arguments pushed since the last call, in program order (32-bit calls).
    pushed: Vec<Expr>,
    /// The comparison the last flag-setting instruction expressed, for the next
    /// conditional branch: the two operands (the second is `0` for a zero test)
    /// and how the flags were set.
    cmp: Option<(Expr, Expr, FlagSrc)>,
    /// Whether this function keeps a frame pointer (`mov ebp, esp` in the
    /// prologue). When it does, `ebp`-relative accesses become named frame slots.
    frame: bool,
    /// The stack pointer's offset from entry, and the registers aliasing it, so a
    /// frame-pointer-less function still gets named `rsp`-relative slots.
    stack: StackSt,
    /// The x64 switch dispatch being assembled, if any. Block-local: the load,
    /// the add and the jump are always consecutive, and the engine tracks the
    /// same shape to resolve the targets. Both have to agree, or the pseudocode
    /// would print a switch beside successors that are not its cases.
    switch: Option<PendingSwitch>,
}

/// The registers an x64 switch dispatch is being built out of: an offset loaded
/// from a table, the base added back, then a jump through the result.
#[derive(Clone)]
struct PendingSwitch {
    dst: Register,
    /// The selector, captured where the table was indexed by it rather than
    /// read at the jump. The two are often the same register — `mov ecx,
    /// [base+rcx*4+D]` then `add rcx, base` — so by the jump it holds an
    /// address, and reading it there names the table entry instead of the value
    /// the program switched on.
    sel: Expr,
    base: Register,
    ready: bool,
}

type Cmp = (Expr, Expr, FlagSrc);

#[allow(clippy::too_many_arguments)]
fn lift_block(
    b: &crate::analysis::engine::BasicBlock,
    an: &Analysis,
    bin: &Binary,
    win64: bool,
    frame: bool,
    entry: BTreeMap<Register, Expr>,
    entry_cmp: Option<Cmp>,
    entry_stack: StackSt,
    db: &Db,
) -> (Vec<Stmt>, BTreeMap<Register, Expr>, Option<Cmp>, StackSt) {
    let mut st = Lift {
        regs: entry,
        cmp: entry_cmp,
        frame,
        stack: entry_stack,
        ..Default::default()
    };
    let mut out = Vec::new();
    for ins in &b.insns {
        let Some(d) = decode(ins.bytes(), ins.addr, an.bits) else {
            continue;
        };
        lift_insn(
            &d,
            &mut st,
            an,
            bin,
            win64,
            ins.target_name.as_deref(),
            &mut out,
            db,
        );
    }
    (out, st.regs, st.cmp, st.stack)
}

fn reg(r: Register) -> Expr {
    Expr::Reg(r.full_register(), r)
}

/// Whether the function keeps a frame pointer, i.e. the entry block sets
/// `ebp = esp` (or `rbp = rsp`). When it does, `ebp`-relative memory becomes
/// named frame slots and the frame bookkeeping is dropped.
fn has_frame_pointer(an: &Analysis, f: &Function) -> bool {
    let Some(entry) = f.blocks.first() else {
        return false;
    };
    entry.insns.iter().any(|ins| {
        decode(ins.bytes(), ins.addr, an.bits).is_some_and(|d| {
            d.mnemonic() == Mnemonic::Mov
                && matches!(d.op0_register(), Register::EBP | Register::RBP)
                && matches!(d.op1_register(), Register::ESP | Register::RSP)
        })
    })
}

/// Is `r` the stack pointer or the frame pointer (in any width)?
fn is_stack_reg(r: Register) -> bool {
    matches!(r.full_register(), Register::RSP | Register::RBP)
}

/// Value of operand `i`, with the current register expressions substituted in.
fn operand(d: &Instruction, st: &Lift, i: u32) -> Expr {
    match d.op_kind(i) {
        OpKind::Register => reg_val(st, d.op_register(i)),
        OpKind::Memory => Expr::Mem(Box::new(mem_addr(d, st))),
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32 => Expr::Const(d.immediate(i) as u32 as u64),
        OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
            Expr::Const(d.immediate(i))
        }
        _ => Expr::Opaque(operand_text(d, i)),
    }
}

/// The expression a register currently holds, or the register itself.
fn reg_val(st: &Lift, r: Register) -> Expr {
    st.regs
        .get(&r.full_register())
        .cloned()
        .unwrap_or_else(|| reg(r))
}

/// The sign-extended displacement of a memory operand. iced zero-extends 32-bit
/// displacements, so a frame offset reads as `- 0x28`, not a huge constant.
fn mem_disp(d: &Instruction) -> i64 {
    let raw = d.memory_displacement64();
    if raw <= 0xffff_ffff && raw & 0x8000_0000 != 0 {
        i64::from(raw as u32 as i32)
    } else {
        raw as i64
    }
}

/// The address expression of a memory operand (no dereference), substituted.
fn mem_addr(d: &Instruction, st: &Lift) -> Expr {
    if d.is_ip_rel_memory_operand() {
        return Expr::Global(d.ip_rel_memory_address());
    }
    let disp = mem_disp(d);
    // A plain `[ebp +/- k]` in a frame-pointer function is a named frame slot.
    if st.frame
        && d.memory_index() == Register::None
        && matches!(d.memory_base(), Register::EBP | Register::RBP)
    {
        return Expr::Stack(disp);
    }
    // In a function without a frame pointer, name a slot addressed off `rsp` or a
    // register that aliases it (MSVC's `mov rax, rsp`), using the stack pointer's
    // tracked offset from entry.
    if !st.frame && d.memory_index() == Register::None && d.memory_base() != Register::None {
        let base = d.memory_base().full_register();
        let off = if base == Register::RSP {
            st.stack.sp
        } else {
            st.stack.alias.get(&base).copied()
        };
        if let Some(off) = off {
            return Expr::Stack(off + disp);
        }
    }
    let mut acc: Option<Expr> = None;
    let add = |e: Expr, acc: &mut Option<Expr>| {
        *acc = Some(match acc.take() {
            Some(a) => Expr::Bin("+", Box::new(a), Box::new(e)),
            None => e,
        });
    };
    if d.memory_base() != Register::None {
        add(reg_val(st, d.memory_base()), &mut acc);
    }
    if d.memory_index() != Register::None {
        let idx = reg_val(st, d.memory_index());
        let scale = d.memory_index_scale();
        let e = if scale > 1 {
            Expr::Bin("*", Box::new(idx), Box::new(Expr::Const(scale as u64)))
        } else {
            idx
        };
        add(e, &mut acc);
    }
    match acc {
        // No base or index: a fixed address, i.e. a global.
        None => Expr::Global(disp as u64),
        Some(a) if disp == 0 => a,
        Some(a) if disp < 0 => Expr::Bin("-", Box::new(a), Box::new(Expr::Const((-disp) as u64))),
        Some(a) => Expr::Bin("+", Box::new(a), Box::new(Expr::Const(disp as u64))),
    }
}

/// Where to assign operand 0 (a register or a memory store).
fn dest(d: &Instruction, st: &Lift) -> Expr {
    match d.op0_kind() {
        OpKind::Register => reg(d.op0_register()),
        OpKind::Memory => Expr::Mem(Box::new(mem_addr(d, st))),
        _ => Expr::Opaque(operand_text(d, 0)),
    }
}

fn is_imm(d: &Instruction, i: u32) -> bool {
    matches!(
        d.op_kind(i),
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// The callee-saved (nonvolatile) registers, whose prologue save and epilogue
/// restore are ABI housekeeping with no observable effect.
fn is_callee_saved(r: Register) -> bool {
    let full = r.full_register();
    matches!(
        full,
        Register::RBX
            | Register::RBP
            | Register::RSI
            | Register::RDI
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    )
        // xmm6-xmm15 are nonvolatile on Win64, so their prologue spill and
        // epilogue reload are the same ABI bookkeeping the integer ones are —
        // and now that the vector moves are lifted, they would otherwise show.
        // Asked by number because `full_register` widens a vector register to
        // its largest form: `XMM6` arrives here as `ZMM6`.
        || (full.is_zmm() && (6..=15).contains(&full.number()))
}

/// Whether an address expression is a named stack slot.
fn is_stack_slot(e: &Expr) -> bool {
    matches!(e, Expr::Stack(_))
}

/// Track the stack pointer and its aliases across one instruction, so a local
/// addressed off `rsp` (or a copy of it) resolves to the right slot later in the
/// function. Anything that moves the stack pointer in a way we do not model
/// leaves it `None`, and a stack access simply stays unnamed rather than wrong.
fn update_stack(st: &mut Lift, d: &Instruction, ptr: i64) {
    use Mnemonic::*;
    let m = d.mnemonic();
    match m {
        Push => {
            if let Some(s) = st.stack.sp.as_mut() {
                *s -= ptr;
            }
        }
        Pop => {
            if d.op0_kind() == OpKind::Register {
                st.stack.alias.remove(&d.op0_register().full_register());
            }
            if let Some(s) = st.stack.sp.as_mut() {
                *s += ptr;
            }
        }
        // A call clobbers the caller-saved registers, so any alias in one is gone.
        Call => {
            for r in CALLER_SAVED {
                st.stack.alias.remove(&r);
            }
        }
        Ret => {}
        _ if d.op0_kind() == OpKind::Register => {
            let dst = d.op0_register().full_register();
            let is_sp = dst == Register::RSP;
            let mut handled = false;
            match m {
                Mov if d.op1_kind() == OpKind::Register => {
                    let src = d.op1_register().full_register();
                    let srcval = if src == Register::RSP {
                        st.stack.sp
                    } else {
                        st.stack.alias.get(&src).copied()
                    };
                    if is_sp {
                        st.stack.sp = srcval;
                        handled = true;
                    } else if let Some(o) = srcval {
                        st.stack.alias.insert(dst, o);
                        handled = true;
                    }
                }
                Lea if d.memory_index() == Register::None => {
                    let base = d.memory_base().full_register();
                    let bo = if base == Register::RSP {
                        st.stack.sp
                    } else {
                        st.stack.alias.get(&base).copied()
                    };
                    if let Some(bo) = bo {
                        let off = bo.saturating_add(mem_disp(d));
                        if is_sp {
                            st.stack.sp = Some(off);
                        } else {
                            st.stack.alias.insert(dst, off);
                        }
                        handled = true;
                    }
                }
                Add | Sub if is_imm(d, 1) => {
                    let mut delta = d.immediate(1) as i64;
                    if m == Sub {
                        delta = -delta;
                    }
                    if is_sp {
                        if let Some(s) = st.stack.sp.as_mut() {
                            *s = s.saturating_add(delta);
                        }
                        handled = true;
                    } else if let Some(o) = st.stack.alias.get(&dst).copied() {
                        st.stack.alias.insert(dst, o.saturating_add(delta));
                        handled = true;
                    }
                }
                _ => {}
            }
            if !handled {
                // The register got some other value, so it no longer aliases the
                // stack pointer; an unmodelled write to `rsp` makes it unknown.
                st.stack.alias.remove(&dst);
                if is_sp {
                    st.stack.sp = None;
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn lift_insn(
    d: &Instruction,
    st: &mut Lift,
    an: &Analysis,
    bin: &Binary,
    win64: bool,
    target_name: Option<&str>,
    out: &mut Vec<Stmt>,
    db: &Db,
) {
    use Mnemonic::*;
    let binset = |st: &Lift, op: &'static str| {
        Stmt::Set(
            dest(d, st),
            Expr::Bin(op, Box::new(operand(d, st, 0)), Box::new(operand(d, st, 1))),
        )
    };
    // AVX arithmetic is three-operand: the destination is written and the two
    // sources are operands 1 and 2. The legacy form multiplies into operand 0
    // itself, which `binset` already reads correctly.
    let vbinset = |st: &Lift, op: &'static str| {
        if d.op_count() >= 3 {
            Stmt::Set(
                dest(d, st),
                Expr::Bin(op, Box::new(operand(d, st, 1)), Box::new(operand(d, st, 2))),
            )
        } else {
            binset(st, op)
        }
    };
    // A few instructions write more than one place. Their extra statements are
    // built here from the state as it stands before the instruction runs, and
    // emitted after the main one, so both read the values the machine read.
    let mut extra: Vec<Stmt> = Vec::new();
    // Build the statement (reading the current register expressions), then
    // update the propagation state from it. Pushes and compares update state
    // directly and emit nothing.
    let stmt: Option<Stmt> = match d.mnemonic() {
        // int3 between functions is alignment padding, not code, and
        // vzeroupper is an AVX state hint with no effect on any value this
        // lifter reads. Both drop because that is what they do to the program.
        Nop | Endbr32 | Endbr64 | Int3 | Vzeroupper => None,
        Mov | Movzx | Movsx | Movsxd => Some(Stmt::Set(dest(d, st), operand(d, st, 1))),
        Lea => {
            // `lea` computes an address expression. Where that expression names
            // storage — a frame slot, a global — the value is its address and
            // reads as `&name`. Where it is arithmetic, the value *is* the
            // arithmetic: `lea ebx, [ebx+2]` is how a compiler writes `ebx + 2`
            // without touching the flags, and `&(ebx + 2)` both adds an
            // operator the machine never applied and says something C does not
            // have — a sum has no address to take.
            let address = mem_addr(d, st);
            Some(Stmt::Set(
                dest(d, st),
                match address {
                    Expr::Stack(_) | Expr::Global(_) => Expr::Addr(Box::new(address)),
                    computed => computed,
                },
            ))
        }
        Add => Some(binset(st, "+")),
        Sub => Some(binset(st, "-")),
        And => Some(binset(st, "&")),
        Or => Some(binset(st, "|")),
        Shl | Sal => Some(binset(st, "<<")),
        // The BMI2 shifts spell the same three shapes with explicit operands;
        // `sarx` is the arithmetic one, read as the same `>>` the lifter
        // prints for `sar` and lets the reader's signedness resolve.
        Shlx => Some(Stmt::Set(
            dest(d, st),
            Expr::Bin(
                "<<",
                Box::new(operand(d, st, 1)),
                Box::new(operand(d, st, 2)),
            ),
        )),
        Shrx | Sarx => Some(Stmt::Set(
            dest(d, st),
            Expr::Bin(
                ">>",
                Box::new(operand(d, st, 1)),
                Box::new(operand(d, st, 2)),
            ),
        )),
        Shr | Sar => Some(binset(st, ">>")),
        // The three-operand form `imul dst, src, imm` computes `src * imm`;
        // the two-operand one multiplies into itself. Reading both through
        // `binset` turned `imul eax, ecx, 5` into `eax = eax * ecx`, a
        // different product from a different pair of inputs.
        Imul if d.op_count() >= 3 => Some(Stmt::Set(
            dest(d, st),
            Expr::Bin(
                "*",
                Box::new(operand(d, st, 1)),
                Box::new(operand(d, st, 2)),
            ),
        )),
        Imul if d.op_count() == 2 => Some(binset(st, "*")),
        // The one-operand widening multiply produces the double-width product
        // in `high:acc`. The low half is the plain product for either
        // signedness, and the high half is that product shifted down — the
        // same width-blind `>>` the sign fill already prints, read as
        // arithmetic or logical per signedness.
        Mul | Imul if d.op_count() == 1 => match wide_mul_regs(d) {
            Some((acc, high, width)) => {
                let product =
                    Expr::Bin("*", Box::new(reg_val(st, acc)), Box::new(operand(d, st, 0)));
                extra.push(Stmt::Set(
                    reg(high),
                    Expr::Bin(
                        ">>",
                        Box::new(product.clone()),
                        Box::new(Expr::Const(u64::from(width * 8))),
                    ),
                ));
                Some(Stmt::Set(reg(acc), product))
            }
            _ => Some(asm_stmt(d)),
        },
        Xor => {
            if d.op0_kind() == OpKind::Register
                && d.op1_kind() == OpKind::Register
                && d.op0_register() == d.op1_register()
            {
                Some(Stmt::Set(dest(d, st), Expr::Const(0)))
            } else {
                Some(binset(st, "^"))
            }
        }
        // `div` and `idiv` divide the double-width value in `edx:eax`, not
        // `eax` alone. `eax / src` is the whole truth only when the high half
        // holds the extension of the low one — `xor edx, edx` ahead of an
        // unsigned divide, `cdq` ahead of a signed one, which is what a
        // compiler emits and what the propagated state can prove. Anything
        // else is a real double-width division that no C expression says, and
        // it stays unmodelled rather than becoming a confident claim about
        // half of its own dividend.
        m @ (Div | Idiv) => match divide_regs(d) {
            Some((acc, high, width)) if dividend_is_extended(st, acc, high, width, m == Idiv) => {
                let lo = reg_val(st, acc);
                let src = operand(d, st, 0);
                // The remainder is a value the instruction really produces, so
                // it is stated. Nothing reads it in the common case and the
                // dead-store pass takes it back out again.
                extra.push(Stmt::Set(
                    reg(high),
                    Expr::Bin("%", Box::new(lo.clone()), Box::new(src.clone())),
                ));
                Some(Stmt::Set(
                    reg(acc),
                    Expr::Bin("/", Box::new(lo), Box::new(src)),
                ))
            }
            _ => Some(asm_stmt(d)),
        },
        // Widening the accumulator in place. `cdqe` is `movsxd rax, eax` with
        // the operands implied, and it is read the same way: as the move it is.
        // Unmodelled it was worse than unhelpful — it writes rax, so the
        // propagated value was dropped at exactly the point it was wanted,
        // right in front of the `mov ecx, [base+rax*4+D]` of a switch.
        Cbw | Cwde | Cdqe => {
            let (wide, narrow) = match d.mnemonic() {
                Cbw => (Register::AX, Register::AL),
                Cwde => (Register::EAX, Register::AX),
                _ => (Register::RAX, Register::EAX),
            };
            Some(Stmt::Set(reg(wide), reg_val(st, narrow)))
        }
        // The sign fill a signed divide runs on first. Emitted as an ordinary
        // statement rather than hidden: when the divide that follows is one
        // this lifter can read, nothing reads the high half and the assignment
        // is dropped as a dead store; when it is not, the reader still sees the
        // register being written.
        Cdq | Cqo | Cwd => {
            let (acc, high, width) = match d.mnemonic() {
                Cwd => (Register::AX, Register::DX, 2),
                Cdq => (Register::EAX, Register::EDX, 4),
                _ => (Register::RAX, Register::RDX, 8),
            };
            Some(Stmt::Set(reg(high), sign_fill(&reg_val(st, acc), width)))
        }
        // Scalar floating point. Two thirds of what this lifter still could not
        // read on a real C runtime was SSE, and a numeric function whose every
        // arithmetic step is a comment is not decompiled at all. A copy is a
        // copy and a multiply is a multiply whatever unit performs it; the
        // registers print as `xmm0` and so say for themselves which unit that
        // is. Only the scalar forms are taken — a packed operation works on
        // several lanes at once and `a * b` would describe one of them.
        //
        // Guarded on an xmm operand because `movsd` is two instructions: the
        // SSE move, and the string move that `rep` drives over memory. Reading
        // a block copy as an assignment would be a bad way to learn that.
        // AVX keeps the two-operand encoding for packed moves but gives the
        // scalar moves a third: `vmovsd xmm1, xmm2, xmm3` copies xmm3's low
        // lane into xmm1, merging xmm2's high half around it. The lane copied
        // is the value; the merge is invisible at scalar pseudocode width.
        Vmovsd | Vmovss if d.op_count() == 3 && touches_xmm(d) => {
            Some(Stmt::Set(dest(d, st), operand(d, st, 2)))
        }
        m if is_sse_move(m) && d.op_count() == 2 && touches_xmm(d) => {
            Some(Stmt::Set(dest(d, st), operand(d, st, 1)))
        }
        m if matches!(
            m,
            Addsd
                | Addss
                | Vaddsd
                | Vaddss
                | Subsd
                | Subss
                | Vsubsd
                | Vsubss
                | Mulsd
                | Mulss
                | Vmulsd
                | Vmulss
                | Divsd
                | Divss
                | Vdivsd
                | Vdivss
        ) && touches_xmm(d) =>
        {
            let op = match d.mnemonic() {
                Addsd | Addss | Vaddsd | Vaddss => "+",
                Subsd | Subss | Vsubsd | Vsubss => "-",
                Mulsd | Mulss | Vmulsd | Vmulss => "*",
                _ => "/",
            };
            Some(vbinset(st, op))
        }
        // Bitwise xor, integer or float lanes alike. `xorps xmm, xmm` — and
        // the VEX `vxorps xmm, xmm, xmm` — is how a compiler writes zero into
        // a float register; against memory (`xorps xmm0, [g]` over a zero
        // constant) it is still an xor, which C says directly.
        m @ (Xorps | Xorpd | Pxor | Vxorps | Vxorpd | Vpxor) => {
            let (a, b) = if matches!(m, Vxorps | Vxorpd | Vpxor) && d.op_count() >= 3 {
                (operand(d, st, 1), operand(d, st, 2))
            } else {
                (operand(d, st, 0), operand(d, st, 1))
            };
            if a == b {
                Some(Stmt::Set(dest(d, st), Expr::Const(0)))
            } else if d.op0_kind() == OpKind::Register {
                Some(Stmt::Set(
                    dest(d, st),
                    Expr::Bin("^", Box::new(a), Box::new(b)),
                ))
            } else {
                Some(asm_stmt(d))
            }
        }
        // The float compare, which a following `ja`/`jbe` reads exactly as the
        // integer one reads `cmp`.
        m if matches!(
            m,
            Comisd | Comiss | Ucomisd | Ucomiss | Vcomisd | Vcomiss | Vucomisd | Vucomiss
        ) && touches_xmm(d) =>
        {
            st.cmp = Some((operand(d, st, 0), operand(d, st, 1), FlagSrc::Compare));
            None
        }
        // Scalar FMA: one rounding does a multiply and an add. The three
        // encodings name which operand is the addend; the multiply always
        // pairs the destination's old value with the remaining source. C has
        // no fused form, and `a * b + c` is the arithmetic the machine does,
        // at the precision it does it at.
        m if fma_of(m).is_some() && d.op_count() == 3 && touches_xmm(d) => {
            let (add_index, neg_product, neg_sum) = fma_of(m).expect("guarded above");
            let mul = |i: u32| operand(d, st, i);
            let (a, b) = match add_index {
                0 => (mul(1), mul(2)),
                1 => (mul(0), mul(2)),
                _ => (mul(0), mul(1)),
            };
            let product = Expr::Bin("*", Box::new(a), Box::new(b));
            let product = if neg_product {
                Expr::Un("-", Box::new(product))
            } else {
                product
            };
            let add = mul(add_index);
            Some(Stmt::Set(
                dest(d, st),
                if neg_sum {
                    Expr::Bin("-", Box::new(product), Box::new(add))
                } else {
                    Expr::Bin("+", Box::new(product), Box::new(add))
                },
            ))
        }
        // Conversions are casts, and C has a notation for those. The AVX forms
        // carry two sources: the converted value is the last one, as with the
        // three-operand scalar move.
        m if cast_of(m).is_some()
            && (d.op_count() == 2 || (d.op_count() == 3 && touches_xmm(d))) =>
        {
            let src = if d.op_count() == 3 { 2 } else { 1 };
            Some(Stmt::Set(
                dest(d, st),
                Expr::Un(
                    cast_of(m).expect("guarded above"),
                    Box::new(operand(d, st, src)),
                ),
            ))
        }
        Neg => Some(Stmt::Set(
            dest(d, st),
            Expr::Un("-", Box::new(operand(d, st, 0))),
        )),
        Not => Some(Stmt::Set(
            dest(d, st),
            Expr::Un("~", Box::new(operand(d, st, 0))),
        )),
        Inc => Some(Stmt::Set(
            dest(d, st),
            Expr::Bin("+", Box::new(operand(d, st, 0)), Box::new(Expr::Const(1))),
        )),
        Dec => Some(Stmt::Set(
            dest(d, st),
            Expr::Bin("-", Box::new(operand(d, st, 0)), Box::new(Expr::Const(1))),
        )),
        // `sbb dst, dst` subtracts itself and the borrow: all-ones or zero,
        // decided by the carry of what ran before it. Where that carry's
        // meaning is known — the comparison before it, a `neg` (borrow iff the
        // value was non-zero), a `test`/`and`/`or` (carry cleared) — the value
        // is exactly C's branchless comparison, which MSVC emits this in place
        // of. Any other flag history stays assembly rather than guessing a
        // borrow.
        Sbb if d.op_count() == 2
            && d.op0_kind() == OpKind::Register
            && d.op1_kind() == OpKind::Register
            && d.op0_register().full_register() == d.op1_register().full_register() =>
        {
            let ones = Expr::Const(match d.op0_register().size() {
                1 => 0xff,
                2 => 0xffff,
                4 => 0xffff_ffff,
                _ => u64::MAX,
            });
            let value = match st.cmp.clone() {
                Some((_, _, FlagSrc::Compare)) => Some(Expr::Ternary(
                    Box::new(condition(Mnemonic::Jb, &st.cmp)),
                    Box::new(ones),
                    Box::new(Expr::Const(0)),
                )),
                Some((l, _, FlagSrc::NegResult)) => Some(Expr::Ternary(
                    Box::new(Expr::Bin("!=", Box::new(l), Box::new(Expr::Const(0)))),
                    Box::new(ones),
                    Box::new(Expr::Const(0)),
                )),
                Some((_, _, FlagSrc::ZeroClearsCf)) => Some(Expr::Const(0)),
                Some((_, _, FlagSrc::Zero)) | Some((_, _, FlagSrc::Bit)) | None => None,
            };
            match value {
                Some(v) => Some(Stmt::Set(dest(d, st), v)),
                None => Some(asm_stmt(d)),
            }
        }
        Push => {
            // A `push ebp` in a frame-pointer function is the prologue frame
            // save, not an argument, so it is not collected.
            let saving_frame = st.frame
                && d.op0_kind() == OpKind::Register
                && d.op0_register().full_register() == Register::RBP;
            if !saving_frame {
                let a = operand(d, st, 0);
                st.pushed.push(a);
            }
            None
        }
        Pop => Some(Stmt::Set(dest(d, st), Expr::Opaque("pop()".into()))),
        Leave => None,
        Cmp => {
            st.cmp = Some((operand(d, st, 0), operand(d, st, 1), FlagSrc::Compare));
            None
        }
        Test => {
            let a = operand(d, st, 0);
            let b = operand(d, st, 1);
            // `test x, x` asks whether x is zero, and reads best that way. With
            // two different operands it is a mask test — the flags come from
            // `a & b` — and keeping only the first operand states something
            // else entirely: `test [rcx+0x10], rdx` became `rcx->field_10 == 0`,
            // which is a different question with a different answer.
            let lhs = if a == b {
                a
            } else {
                Expr::Bin("&", Box::new(a), Box::new(b))
            };
            st.cmp = Some((lhs, Expr::Const(0), FlagSrc::ZeroClearsCf));
            None
        }
        // `bt` reads one bit into the carry flag, and the branch after it asks
        // about exactly that bit. `bts`/`btr` set or clear the bit first, and
        // the flag still reflects the bit as it was — which is what the
        // recorded comparison keeps, on the value read before the write.
        m @ (Bt | Bts | Btr) if d.op_count() == 2 => {
            let val = operand(d, st, 0);
            let idx = operand(d, st, 1);
            let bit = Expr::Bin(
                "&",
                Box::new(Expr::Bin(
                    ">>",
                    Box::new(val.clone()),
                    Box::new(idx.clone()),
                )),
                Box::new(Expr::Const(1)),
            );
            st.cmp = Some((bit, Expr::Const(1), FlagSrc::Bit));
            match m {
                Bt => None,
                Bts => Some(Stmt::Set(
                    dest(d, st),
                    Expr::Bin(
                        "|",
                        Box::new(val),
                        Box::new(Expr::Bin("<<", Box::new(Expr::Const(1)), Box::new(idx))),
                    ),
                )),
                _ => Some(Stmt::Set(
                    dest(d, st),
                    Expr::Bin(
                        "&",
                        Box::new(val),
                        Box::new(Expr::Un(
                            "~",
                            Box::new(Expr::Bin("<<", Box::new(Expr::Const(1)), Box::new(idx))),
                        )),
                    ),
                )),
            }
        }
        // A rotate has no C operator. With an immediate count the exact
        // expansion is small and pure: `(x >> n) | (x << (width - n))`. A
        // register count is masked by the hardware, which C's shifts are not,
        // so it stays assembly instead of printing a shift C might refuse.
        m @ (Rol | Ror)
            if d.op_count() == 2 && d.op0_kind() == OpKind::Register && is_imm(d, 1) =>
        {
            let width = d.op0_register().size() as u64 * 8;
            let n = d.immediate(1);
            if n == 0 || n >= width {
                Some(asm_stmt(d))
            } else {
                let x = operand(d, st, 0);
                let (first_op, first_n, second_op, second_n) = match m {
                    Ror => (">>", n, "<<", width - n),
                    _ => ("<<", n, ">>", width - n),
                };
                Some(Stmt::Set(
                    dest(d, st),
                    Expr::Bin(
                        "|",
                        Box::new(Expr::Bin(
                            first_op,
                            Box::new(x.clone()),
                            Box::new(Expr::Const(first_n)),
                        )),
                        Box::new(Expr::Bin(
                            second_op,
                            Box::new(x),
                            Box::new(Expr::Const(second_n)),
                        )),
                    ),
                ))
            }
        }
        Call => {
            let call = lift_call(d, st, an, bin, win64, target_name, db);
            let ret = if an.bits == 32 {
                Register::EAX
            } else {
                Register::RAX
            };
            Some(Stmt::Set(reg(ret), call))
        }
        // The return reads the register the way any other read does: whatever
        // value propagation recovered is printed, and with none the register
        // names itself.
        Ret => Some(Stmt::Ret(Some(reg_val(
            st,
            if an.bits == 32 {
                Register::EAX
            } else {
                Register::RAX
            },
        )))),
        Jmp => Some(match branch_target(d) {
            Some(t) => Stmt::Goto(t),
            // An indexed memory jump is a switch; its selector is the index. The
            // case targets come from the block's engine-resolved successors.
            None if d.op0_kind() == OpKind::Memory && d.memory_index() != Register::None => {
                Stmt::Switch(reg_val(st, d.memory_index()))
            }
            // A jump through a register is a switch too when it is the end of
            // the x64 dispatch shape. The selector is the register the table was
            // indexed by, not the one being jumped through: by now that one
            // holds an address, and `switch (rcx)` would name the wrong value.
            None if st
                .switch
                .as_ref()
                .is_some_and(|p| p.ready && d.op0_register().full_register() == p.dst) =>
            {
                Stmt::Switch(st.switch.as_ref().expect("checked above").sel.clone())
            }
            None => asm_stmt(d),
        }),
        m if is_jcc(m) => Some(match branch_target(d) {
            Some(t) => Stmt::Branch(condition(m, &st.cmp), t),
            None => asm_stmt(d),
        }),
        // `setcc dst` is a boolean: `dst = (comparison)`.
        m if is_setcc(m) && cc_to_jcc(m).is_some() => {
            let cond = condition(cc_to_jcc(m).unwrap(), &st.cmp);
            Some(Stmt::Set(dest(d, st), cond))
        }
        // `cmovcc dst, src` is a conditional move: `dst = cond ? src : dst`.
        m if is_cmovcc(m) && cc_to_jcc(m).is_some() => {
            let cond = condition(cc_to_jcc(m).unwrap(), &st.cmp);
            let src = operand(d, st, 1);
            let keep = operand(d, st, 0);
            Some(Stmt::Set(
                dest(d, st),
                Expr::Ternary(Box::new(cond), Box::new(src), Box::new(keep)),
            ))
        }
        _ => Some(asm_stmt(d)),
    };

    // Maintain the recovered comparison for a following `jcc`, which may be in a
    // later block (a `cmp` shared by several conditional jumps). A flag-setting
    // arithmetic op records "result vs zero"; anything that clobbers the flags
    // without being a recognised comparison invalidates it, so a stale compare
    // is never carried into the branch that reads it.
    let m = d.mnemonic();
    if sets_zero_flags(m) {
        if let Some(Stmt::Set(dst, _)) = &stmt {
            // `and`/`or`/`xor` clear the carry flag, defined, and `neg` sets it
            // to the operand's non-zero-ness; `sbb` reads exactly that carry,
            // so the recorded comparison keeps which one set it. The rest
            // leave a carry this lifter does not reconstruct.
            let src = if m == Mnemonic::Neg {
                FlagSrc::NegResult
            } else if matches!(m, Mnemonic::And | Mnemonic::Or | Mnemonic::Xor) {
                FlagSrc::ZeroClearsCf
            } else {
                FlagSrc::Zero
            };
            st.cmp = Some((dst.clone(), Expr::Const(0), src));
        }
    } else if !is_comparison(m) && !preserves_flags(m) {
        st.cmp = None;
    }

    // Follow the x64 switch dispatch, so the jump that ends it can be read as
    // one. Updated after the statement is built, so the `jmp` still sees the
    // state the `add` before it left.
    let (next_switch, completes_dispatch) = switch_step(d, st, st.switch.clone());
    // The table load is dispatch mechanics too, and on x64 it destroys the very
    // register it indexed by: `mov ecx, [base+rcx*4+D]` writes ecx, which zeroes
    // the top half of rcx. Left in, it sits directly above `switch (rcx)` and
    // makes the selector name a value the machine no longer holds. It is taken
    // back out only once the `add` proves this really was a dispatch, so a load
    // that merely looks like one is never hidden.
    if completes_dispatch {
        if let Some(p) = &next_switch {
            if matches!(out.last(), Some(Stmt::Set(Expr::Reg(root, _), Expr::Mem(_))) if *root == p.dst)
            {
                out.pop();
            }
        }
    }
    st.switch = next_switch;

    let ptr = if an.bits == 64 { 8 } else { 4 };
    update_stack(st, d, ptr);

    if let Some(s) = stmt {
        update_state(st, &s);
        // Drop pure stack bookkeeping so it does not clutter the output:
        //   - any write to the stack pointer (frame allocation and cleanup), and
        //     the frame-pointer setup/teardown in a frame-pointer function;
        //   - a copy of the stack/frame pointer into a register (the frame-base
        //     alias, `mov rax, rsp`), which the stack tracker has already noted;
        //   - a callee-saved register spilled to, or restored from, a stack slot.
        // None of these have an observable effect, so hiding them is faithful.
        let housekeeping = matches!(
            &s,
            Stmt::Set(Expr::Reg(root, _), _)
                if *root == Register::RSP || (st.frame && *root == Register::RBP)
        ) || matches!(
            &s,
            Stmt::Set(Expr::Reg(..), Expr::Reg(sr, _)) if is_stack_reg(*sr)
        ) || matches!(
            &s,
            Stmt::Set(Expr::Mem(a), Expr::Reg(sr, _)) if is_callee_saved(*sr) && is_stack_slot(a)
        ) || matches!(
            &s,
            Stmt::Set(Expr::Reg(dr, _), Expr::Mem(a)) if is_callee_saved(*dr) && is_stack_slot(a)
        )
        // The `add` that turns a table entry into an address is the dispatch
        // itself, not something the program computes. Dropping it also leaves
        // the selector meaning what it says: the register it names is often the
        // one this `add` would overwrite, and a `switch (rcx)` printed under a
        // fresh `rcx = ...` reads as the wrong value. The load above it is then
        // dead and goes the same way.
        || completes_dispatch;
        if !housekeeping {
            out.push(s);
        }
    }
    for s in extra {
        update_state(st, &s);
        out.push(s);
    }
}

/// The instructions that leave a comparison behind for a later branch to read.
/// The float compares belong here with `cmp` and `test`, as do the bit tests:
/// they are how a comparison is made, so treating them as flag clobbers would
/// throw away the comparison they had just recorded.
fn is_comparison(m: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        m,
        Cmp | Test
            | Bt
            | Bts
            | Btr
            | Comisd
            | Comiss
            | Ucomisd
            | Ucomiss
            | Vcomisd
            | Vcomiss
            | Vucomisd
            | Vucomiss
    )
}

/// Whether any operand is a vector register, which is what separates the SSE
/// `movsd xmm0, [rax]` from the string `movsd` that copies memory under `rep`.
fn touches_xmm(d: &Instruction) -> bool {
    (0..d.op_count()).any(|i| {
        d.op_kind(i) == OpKind::Register && {
            let r = d.op_register(i);
            r.is_xmm() || r.is_ymm() || r.is_zmm()
        }
    })
}

/// The vector moves that are plain copies. The packed ones are here too: a
/// 128-bit spill and reload is still a copy of whatever it held, and saying so
/// claims nothing about the lanes inside it. AVX spells the same moves with a
/// leading `v`.
fn is_sse_move(m: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        m,
        Movsd
            | Movss
            | Movaps
            | Movups
            | Movapd
            | Movupd
            | Movdqa
            | Movdqu
            | Movd
            | Movq
            | Vmovsd
            | Vmovss
            | Vmovaps
            | Vmovups
            | Vmovapd
            | Vmovupd
            | Vmovdqa
            | Vmovdqu
            | Vmovd
            | Vmovq
    )
}

/// The C cast a conversion instruction performs, or `None` if it is not one.
fn cast_of(m: Mnemonic) -> Option<&'static str> {
    use Mnemonic::*;
    Some(match m {
        Cvtsi2sd | Cvtss2sd => "(double)",
        Cvtsi2ss | Cvtsd2ss => "(float)",
        Cvttsd2si | Cvttss2si | Cvtsd2si | Cvtss2si => "(int)",
        // the AVX spellings of the same conversions
        Vcvtsi2sd | Vcvtss2sd => "(double)",
        Vcvtsi2ss | Vcvtsd2ss => "(float)",
        Vcvttsd2si | Vcvttss2si | Vcvtsd2si | Vcvtss2si => "(int)",
        _ => return None,
    })
}

/// The scalar FMA instructions. Returns which of the three operands is the
/// additive term (0 = the destination's old value), and the signs the product
/// and the sum carry. Multiplication commutes, so which of the remaining two
/// multiplies first does not matter; which one is added does.
fn fma_of(m: Mnemonic) -> Option<(u32, bool, bool)> {
    use Mnemonic::*;
    Some(match m {
        Vfmadd132sd | Vfmadd132ss => (1, false, false),
        Vfmadd213sd | Vfmadd213ss => (2, false, false),
        Vfmadd231sd | Vfmadd231ss => (0, false, false),
        Vfmsub132sd | Vfmsub132ss => (1, false, true),
        Vfmsub213sd | Vfmsub213ss => (2, false, true),
        Vfmsub231sd | Vfmsub231ss => (0, false, true),
        Vfnmadd132sd | Vfnmadd132ss => (1, true, false),
        Vfnmadd213sd | Vfnmadd213ss => (2, true, false),
        Vfnmadd231sd | Vfnmadd231ss => (0, true, false),
        Vfnmsub132sd | Vfnmsub132ss => (1, true, true),
        Vfnmsub213sd | Vfnmsub213ss => (2, true, true),
        Vfnmsub231sd | Vfnmsub231ss => (0, true, true),
        _ => return None,
    })
}

/// The accumulator and high-half registers a `div`/`idiv` uses, taken from the
/// width of its divisor. The 8-bit form divides `ax` on its own and does not
/// fit this shape, so it is left unmodelled.
fn divide_regs(d: &Instruction) -> Option<(Register, Register, u32)> {
    let bytes = match d.op0_kind() {
        OpKind::Register => d.op0_register().size(),
        OpKind::Memory => d.memory_size().size(),
        _ => return None,
    };
    match bytes {
        2 => Some((Register::AX, Register::DX, 2)),
        4 => Some((Register::EAX, Register::EDX, 4)),
        8 => Some((Register::RAX, Register::RDX, 8)),
        _ => None,
    }
}

/// The accumulator and high-half registers a one-operand `mul`/`imul` writes,
/// taken from the width of its operand. The 8-bit forms leave the product's
/// low half in `ax` alone and do not fit this shape, so they stay unmodelled.
fn wide_mul_regs(d: &Instruction) -> Option<(Register, Register, u32)> {
    let bytes = match d.op0_kind() {
        OpKind::Register => d.op0_register().size(),
        OpKind::Memory => d.memory_size().size(),
        _ => return None,
    };
    match bytes {
        2 => Some((Register::AX, Register::DX, 2)),
        4 => Some((Register::EAX, Register::EDX, 4)),
        8 => Some((Register::RAX, Register::RDX, 8)),
        _ => None,
    }
}

/// What `cdq`/`cqo` — or the `sar reg, width-1` a compiler writes instead —
/// leaves in the high half: every bit set to the accumulator's sign.
fn sign_fill(lo: &Expr, width: u32) -> Expr {
    Expr::Bin(
        ">>",
        Box::new(lo.clone()),
        Box::new(Expr::Const(u64::from(width * 8 - 1))),
    )
}

/// Whether the high half provably holds no more than the extension of the low
/// one, which is what makes `acc / src` the whole division rather than a part
/// of it. Unknown counts as no: a register we have not tracked could hold
/// anything, and the point of asking is to refuse in exactly that case.
fn dividend_is_extended(
    st: &Lift,
    acc: Register,
    high: Register,
    width: u32,
    signed: bool,
) -> bool {
    let held = reg_val(st, high);
    if signed {
        held == sign_fill(&reg_val(st, acc), width)
    } else {
        held == Expr::Const(0)
    }
}

/// Advance the x64 switch dispatch by one instruction.
///
/// The engine tracks the same three steps to resolve the table; this side only
/// needs to know which register was the selector, so that the `jmp` reads as a
/// switch on the right value. Kept as permissive as the engine's, so the two
/// agree on which jumps are switches — one recognising it and the other not is
/// how a `switch` would come to be printed beside blocks that are not its cases.
fn switch_step(
    d: &Instruction,
    st: &Lift,
    cur: Option<PendingSwitch>,
) -> (Option<PendingSwitch>, bool) {
    // `mov r32, [B + I*4 + D]` — the load of one table entry.
    if d.mnemonic() == Mnemonic::Mov
        && d.op_count() == 2
        && d.op0_kind() == OpKind::Register
        && d.op1_kind() == OpKind::Memory
        && d.memory_index_scale() == 4
        && d.memory_index() != Register::None
        && d.memory_base() != Register::None
    {
        return (
            Some(PendingSwitch {
                dst: d.op0_register().full_register(),
                sel: reg_val(st, d.memory_index()),
                base: d.memory_base().full_register(),
                ready: false,
            }),
            false,
        );
    }
    let Some(mut p) = cur else {
        return (None, false);
    };
    // `add dst, B` — the displacement becomes an address.
    if !p.ready
        && d.mnemonic() == Mnemonic::Add
        && d.op_count() == 2
        && d.op0_kind() == OpKind::Register
        && d.op0_register().full_register() == p.dst
        && d.op1_kind() == OpKind::Register
        && d.op1_register().full_register() == p.base
    {
        p.ready = true;
        return (Some(p), true);
    }
    // Anything else writing the register the shape resolves into means it no
    // longer describes what the machine holds. The selector needs no such check:
    // it was copied at the load, not read at the jump.
    if d.op0_kind() == OpKind::Register && d.op0_register().full_register() == p.dst {
        return (None, false);
    }
    (Some(p), false)
}

/// Update the propagation state from an emitted statement: remember a register's
/// new pure value, forget it otherwise, and drop memory-reading values whenever
/// a store or call could have changed memory.
fn update_state(st: &mut Lift, s: &Stmt) {
    // An instruction we could not model still ran. Forget what it wrote, or the
    // value propagated past it is the one it just overwrote — `mov rax, 5; div
    // rcx; mov rbx, rax` would otherwise print `rbx = 5`, which is not merely
    // vague but false. Memory is dropped too: we cannot see where it wrote.
    if let Stmt::Asm { defs, .. } = s {
        for r in defs {
            st.regs.remove(r);
        }
        if !defs.is_empty() {
            st.regs.retain(|_, e| !reads_mem(e));
        }
        return;
    }
    let clobbers_mem = matches!(s, Stmt::Set(Expr::Mem(_), _))
        || matches!(s, Stmt::Set(_, src) if contains_call(src));
    if clobbers_mem {
        st.regs.retain(|_, e| !reads_mem(e));
    }
    if let Stmt::Set(Expr::Reg(root, _), src) = s {
        if contains_call(src) {
            for r in CALLER_SAVED {
                st.regs.remove(&r);
            }
        }
        // The stack and frame pointers are never propagated: their values are
        // pure bookkeeping, and substituting them would corrupt the base of a
        // memory access (an `[ebp + k]` becoming a stale `[esp + k]`).
        if is_stack_reg(*root) {
            st.regs.remove(root);
        } else if is_pure(src) {
            // A hostile straight-line chain of dependent arithmetic (`add rax,1`
            // repeated) would otherwise grow an arbitrarily deep expression tree
            // as each instruction substitutes its operand's value, and every
            // recursive pass over it (fold, liveness, rendering) would overflow
            // the native stack. Cap what we carry: beyond this size we stop
            // inlining the register and keep its name, so no tree ever recurses
            // deeper than a couple of hundred levels.
            if expr_nodes(src) > MAX_EXPR_NODES {
                st.regs.insert(*root, reg(*root));
            } else {
                st.regs.insert(*root, src.clone());
            }
        } else {
            st.regs.remove(root);
        }
    }
}

/// How many nodes an expression tree has; the bound we use to stop propagating
/// ever-deeper register substitutions (see `update_state`).
const MAX_EXPR_NODES: usize = 512;

fn expr_nodes(e: &Expr) -> usize {
    match e {
        Expr::Bin(_, l, r) => 1 + expr_nodes(l) + expr_nodes(r),
        Expr::Mem(i) | Expr::Addr(i) | Expr::Un(_, i) => 1 + expr_nodes(i),
        Expr::Ternary(c, a, b) => 1 + expr_nodes(c) + expr_nodes(a) + expr_nodes(b),
        Expr::Phi(_, v) => 1 + v.iter().map(expr_nodes).sum::<usize>(),
        Expr::Call(_, args) => 1 + args.iter().map(expr_nodes).sum::<usize>(),
        Expr::Const(_) | Expr::Reg(..) | Expr::Stack(_) | Expr::Global(_) | Expr::Opaque(_) => 1,
    }
}

fn lift_call(
    d: &Instruction,
    st: &mut Lift,
    an: &Analysis,
    bin: &Binary,
    win64: bool,
    target_name: Option<&str>,
    db: &Db,
) -> Expr {
    let target = call_target(d, an, bin);
    let name = target_name
        .map(strip_module)
        .or_else(|| target.map(|t| an.label(t)))
        .unwrap_or_else(|| indirect_callee(d));

    let args = if an.bits == 32 {
        // Right-to-left pushes: reverse to C order; whatever was pushed since the
        // last call is the argument list. Each was snapshotted at its push.
        let mut a = std::mem::take(&mut st.pushed);
        a.reverse();
        a
    } else {
        st.pushed.clear();
        // Known APIs have authoritative prototypes. For a direct call to code
        // Knife recovered itself, conservatively inspect the callee instead:
        // an ABI register is a parameter only when some entry-reachable path
        // reads it before an unconditional write. Taking the highest used ABI
        // slot preserves positional gaps (`rdx` implies a two-argument call).
        let stored_arity = target.and_then(|address| {
            db.prototype(address.wrapping_sub(an.display_base))
                .map(|prototype| prototype.params.len())
        });
        let n = stored_arity
            .or_else(|| arity(&name))
            .or_else(|| target.and_then(|address| internal_arity(an, address, win64)))
            .unwrap_or(0);
        arg_registers(win64)
            .iter()
            .take(n)
            .map(|&r| reg_val(st, r))
            .collect()
    };
    st.pushed.clear();
    Expr::Call(name, args)
}

/// Recover a 64-bit internal callee's positional ABI arity from register
/// use-before-definition. This is deliberately path-sensitive only for the
/// one fact we need: after an unconditional write, that path can no longer
/// prove the incoming register was consumed. Conditional writes leave the path
/// live because the old argument can survive them.
fn internal_arity(an: &Analysis, target: u64, win64: bool) -> Option<usize> {
    let function = an.find_function(target)?;
    let block_index: BTreeMap<u64, usize> = function
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let entry = *block_index.get(&function.addr)?;
    let mut highest = None;

    for (position, &argument) in arg_registers(win64).iter().enumerate() {
        let mut pending = vec![entry];
        let mut visited = BTreeSet::new();
        let mut consumed = false;

        while let Some(index) = pending.pop() {
            if !visited.insert(index) {
                continue;
            }
            let block = &function.blocks[index];
            let mut incoming_survives = true;
            let mut info = InstructionInfoFactory::new();
            for raw in &block.insns {
                let Some(instruction) = decode(raw.bytes(), raw.addr, an.bits) else {
                    continue;
                };
                let accesses: Vec<OpAccess> = info
                    .info(&instruction)
                    .used_registers()
                    .iter()
                    .filter(|used| {
                        used.register().is_gpr() && used.register().full_register() == argument
                    })
                    .map(|used| used.access())
                    .collect();
                if accesses.iter().any(|access| {
                    matches!(
                        access,
                        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite
                    )
                }) {
                    consumed = true;
                    break;
                }
                if accesses
                    .iter()
                    .any(|access| matches!(access, OpAccess::Write | OpAccess::ReadWrite))
                {
                    incoming_survives = false;
                    break;
                }
            }
            if consumed {
                break;
            }
            if incoming_survives {
                pending.extend(
                    block
                        .succ
                        .iter()
                        .filter_map(|successor| block_index.get(successor).copied()),
                );
            }
        }
        if consumed {
            highest = Some(position + 1);
        }
    }
    highest
}

fn is_pure(e: &Expr) -> bool {
    match e {
        Expr::Const(_) | Expr::Reg(..) | Expr::Stack(_) | Expr::Global(_) => true,
        Expr::Mem(a) | Expr::Addr(a) | Expr::Un(_, a) => is_pure(a),
        Expr::Bin(_, l, r) => is_pure(l) && is_pure(r),
        Expr::Phi(_, values) => values.iter().all(is_pure),
        Expr::Ternary(c, a, b) => is_pure(c) && is_pure(a) && is_pure(b),
        // A call is never pure; an opaque value is not safe to duplicate.
        Expr::Call(..) | Expr::Opaque(_) => false,
    }
}

fn reads_mem(e: &Expr) -> bool {
    match e {
        Expr::Mem(_) => true,
        Expr::Addr(a) | Expr::Un(_, a) => reads_mem(a),
        Expr::Bin(_, l, r) => reads_mem(l) || reads_mem(r),
        Expr::Phi(_, values) => values.iter().any(reads_mem),
        Expr::Ternary(c, a, b) => reads_mem(c) || reads_mem(a) || reads_mem(b),
        Expr::Call(_, args) => args.iter().any(reads_mem),
        Expr::Const(_) | Expr::Reg(..) | Expr::Stack(_) | Expr::Global(_) | Expr::Opaque(_) => {
            false
        }
    }
}

fn contains_call(e: &Expr) -> bool {
    match e {
        Expr::Call(..) => true,
        Expr::Mem(a) | Expr::Addr(a) => contains_call(a),
        Expr::Bin(_, l, r) => contains_call(l) || contains_call(r),
        Expr::Phi(_, values) => values.iter().any(contains_call),
        Expr::Ternary(c, a, b) => contains_call(c) || contains_call(a) || contains_call(b),
        _ => false,
    }
}

// ── pass: dead-store elimination ────────────────────────────────────────────

const CALLER_SAVED: [Register; 7] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

/// Remove assignments to a register whose result is never read before being
/// overwritten and is not live out of the block. Liveness is a standard
/// backward fixpoint over the control-flow graph, so a value used only in a
/// later block is kept.
fn dead_store_elim(blocks: &mut [IrBlock]) {
    let index: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start, i))
        .collect();

    // Per-block gen/kill for registers, then live-in/live-out to a fixpoint.
    let n = blocks.len();
    let mut live_out: Vec<BTreeSet<Register>> = vec![BTreeSet::new(); n];
    let mut live_in: Vec<BTreeSet<Register>> = vec![BTreeSet::new(); n];

    loop {
        let mut changed = false;
        for i in (0..n).rev() {
            let mut out = BTreeSet::new();
            for s in &blocks[i].succ {
                if let Some(&j) = index.get(s) {
                    out.extend(live_in[j].iter().copied());
                }
            }
            // live_in = uses ∪ (live_out − defs), walked backward through stmts.
            let mut cur = out.clone();
            for st in blocks[i].stmts.iter().rev() {
                apply_liveness(st, &mut cur);
            }
            if out != live_out[i] || cur != live_in[i] {
                live_out[i] = out;
                live_in[i] = cur;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // With liveness known, drop dead register assignments block by block.
    for i in 0..n {
        let mut live = live_out[i].clone();
        let mut keep = vec![true; blocks[i].stmts.len()];
        // A call whose result register is dead becomes a bare call statement,
        // so it reads `f(x);` rather than `eax = f(x);`.
        let mut voidify: Vec<usize> = Vec::new();
        for (k, st) in blocks[i].stmts.iter().enumerate().rev() {
            if let Stmt::Set(Expr::Reg(root, _), src) = st {
                let dead = !live.contains(root);
                if dead {
                    if contains_call(src) {
                        voidify.push(k); // keep the side effect, drop the assignment
                    } else {
                        keep[k] = false;
                        continue;
                    }
                }
            }
            apply_liveness(st, &mut live);
        }
        for k in voidify {
            if let Stmt::Set(_, src) = &blocks[i].stmts[k] {
                blocks[i].stmts[k] = Stmt::CallVoid(src.clone());
            }
        }
        let mut k = 0;
        blocks[i].stmts.retain(|_| {
            let keep_it = keep[k];
            k += 1;
            keep_it
        });
    }
}

/// Update the live set for one statement, walked backward: reads become live,
/// a register definition is killed.
fn apply_liveness(s: &Stmt, live: &mut BTreeSet<Register>) {
    match s {
        Stmt::Set(dst, src) => {
            if let Expr::Reg(root, _) = dst {
                live.remove(root);
            } else if let Expr::Mem(a) = dst {
                reads_regs(a, live);
            }
            reads_regs(src, live);
        }
        Stmt::CallVoid(e) | Stmt::Branch(e, _) | Stmt::Ret(Some(e)) | Stmt::Switch(e) => {
            reads_regs(e, live)
        }
        // What an unmodelled instruction reads is still read. Falling through
        // here meant the store feeding a `div` had no visible consumer, so the
        // dead-store pass deleted the very value being divided.
        Stmt::Asm { defs, uses, .. } => {
            for r in defs {
                live.remove(r);
            }
            for r in uses {
                live.insert(*r);
            }
        }
        _ => {}
    }
}

fn reads_regs(e: &Expr, live: &mut BTreeSet<Register>) {
    match e {
        Expr::Reg(root, _) => {
            live.insert(*root);
        }
        Expr::Mem(a) | Expr::Addr(a) | Expr::Un(_, a) => reads_regs(a, live),
        Expr::Bin(_, l, r) => {
            reads_regs(l, live);
            reads_regs(r, live);
        }
        // The register counts as read, not only the values merged into it. If
        // the join cannot be lowered to a conditional it is printed as that
        // register, and the assignments giving it its values have to still be
        // there — otherwise the reader is sent to a register nothing ever sets.
        Expr::Phi(register, values) => {
            live.insert(*register);
            values.iter().for_each(|value| reads_regs(value, live));
        }
        Expr::Ternary(c, a, b) => {
            reads_regs(c, live);
            reads_regs(a, live);
            reads_regs(b, live);
        }
        Expr::Call(_, args) => args.iter().for_each(|a| reads_regs(a, live)),
        Expr::Const(_) | Expr::Stack(_) | Expr::Global(_) | Expr::Opaque(_) => {}
    }
}

// ── pass: constant folding ──────────────────────────────────────────────────

fn fold_stmt(s: &mut Stmt) {
    match s {
        Stmt::Set(dst, src) => {
            if let Expr::Mem(a) = dst {
                fold(a);
            }
            fold(src);
        }
        Stmt::CallVoid(e) | Stmt::Branch(e, _) | Stmt::Ret(Some(e)) | Stmt::Switch(e) => fold(e),
        _ => {}
    }
}

fn fold(e: &mut Expr) {
    match e {
        // No constant folding under a unary: the result depends on the width
        // the instruction worked at, and `neg eax` of 5 is 0xfffffffb, not the
        // 64-bit 0xfffffffffffffffb that folding here would produce.
        Expr::Mem(a) | Expr::Addr(a) | Expr::Un(_, a) => fold(a),
        Expr::Bin(op, l, r) => {
            fold(l);
            fold(r);
            if let (Expr::Const(a), Expr::Const(b)) = (l.as_ref(), r.as_ref()) {
                if let Some(v) = eval(op, *a, *b) {
                    *e = Expr::Const(v);
                }
            }
        }
        Expr::Phi(_, values) => values.iter_mut().for_each(fold),
        Expr::Ternary(c, a, b) => {
            fold(c);
            fold(a);
            fold(b);
        }
        Expr::Call(_, args) => args.iter_mut().for_each(fold),
        Expr::Const(_) | Expr::Reg(..) | Expr::Stack(_) | Expr::Global(_) | Expr::Opaque(_) => {}
    }
}

fn eval(op: &str, a: u64, b: u64) -> Option<u64> {
    Some(match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "&" => a & b,
        "|" => a | b,
        "^" => a ^ b,
        "<<" => a.checked_shl(b as u32)?,
        ">>" => a.checked_shr(b as u32)?,
        _ => return None,
    })
}

// ── rendering ───────────────────────────────────────────────────────────────

/// A deliberately small C type lattice. These are facts Knife can justify from
/// the ABI and well-known prototypes; everything else remains an integer-sized
/// opaque value instead of acquiring a speculative source-level type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CType {
    Unknown,
    Void,
    Bool,
    Int,
    Size,
    SignedSize,
    CharPtr,
    ConstCharPtr,
    WCharPtr,
    ConstWCharPtr,
    VoidPtr,
    ConstVoidPtr,
}

impl CType {
    fn c(self) -> &'static str {
        match self {
            Self::Unknown => "uintptr_t",
            Self::Void => "void",
            Self::Bool => "bool",
            Self::Int => "int",
            Self::Size => "size_t",
            Self::SignedSize => "ssize_t",
            Self::CharPtr => "char *",
            Self::ConstCharPtr => "const char *",
            Self::WCharPtr => "wchar_t *",
            Self::ConstWCharPtr => "const wchar_t *",
            Self::VoidPtr => "void *",
            Self::ConstVoidPtr => "const void *",
        }
    }

    fn merge(self, other: Self) -> Self {
        use CType::*;
        match (self, other) {
            (a, b) if a == b => a,
            (Unknown, b) => b,
            (a, Unknown) => a,
            (CharPtr, ConstCharPtr) | (ConstCharPtr, CharPtr) => ConstCharPtr,
            (WCharPtr, ConstWCharPtr) | (ConstWCharPtr, WCharPtr) => ConstWCharPtr,
            (
                CharPtr | ConstCharPtr | WCharPtr | ConstWCharPtr | VoidPtr | ConstVoidPtr,
                CharPtr | ConstCharPtr | WCharPtr | ConstWCharPtr | VoidPtr | ConstVoidPtr,
            ) => VoidPtr,
            (Int | Size | SignedSize | Bool, Int | Size | SignedSize | Bool) => Unknown,
            _ => Unknown,
        }
    }
}

fn stored_prototype<'a>(
    an: &Analysis,
    db: &'a Db,
    name: &str,
) -> Option<&'a crate::db::UserPrototype> {
    let function = an.find_by_name(name)?;
    db.prototype(function.addr.wrapping_sub(an.display_base))
}

fn user_type_fact(value: &str) -> CType {
    match value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .as_str()
    {
        "void" => CType::Void,
        "bool" => CType::Bool,
        "int" => CType::Int,
        "size_t" => CType::Size,
        "ssize_t" => CType::SignedSize,
        "char *" => CType::CharPtr,
        "const char *" => CType::ConstCharPtr,
        "wchar_t *" => CType::WCharPtr,
        "const wchar_t *" => CType::ConstWCharPtr,
        "void *" => CType::VoidPtr,
        "const void *" => CType::ConstVoidPtr,
        other if other.contains('*') && other.starts_with("const ") => CType::ConstVoidPtr,
        other if other.contains('*') => CType::VoidPtr,
        _ => CType::Unknown,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Param {
    Reg(Register),
    Stack(i64),
}

fn prototype(name: &str) -> Option<(CType, &'static [CType])> {
    use CType::*;
    let bare = crate::analysis::thunks::bare_name(name);
    Some(match bare {
        "malloc" => (VoidPtr, &[Size]),
        "calloc" => (VoidPtr, &[Size, Size]),
        "realloc" => (VoidPtr, &[VoidPtr, Size]),
        "free" => (Void, &[VoidPtr]),
        "strlen" => (Size, &[ConstCharPtr]),
        "atoi" => (Int, &[ConstCharPtr]),
        "puts" | "system" => (Int, &[ConstCharPtr]),
        "strcpy" | "strcat" | "lstrcpyA" | "lstrcatA" => (CharPtr, &[CharPtr, ConstCharPtr]),
        "strncpy" | "strncat" => (CharPtr, &[CharPtr, ConstCharPtr, Size]),
        "wcscpy" | "wcscat" | "lstrcpyW" | "lstrcatW" => (WCharPtr, &[WCharPtr, ConstWCharPtr]),
        "wcslen" => (Size, &[ConstWCharPtr]),
        "memcpy" | "memmove" => (VoidPtr, &[VoidPtr, ConstVoidPtr, Size]),
        "memset" => (VoidPtr, &[VoidPtr, Int, Size]),
        "strcmp" => (Int, &[ConstCharPtr, ConstCharPtr]),
        "wcscmp" => (Int, &[ConstWCharPtr, ConstWCharPtr]),
        "gets" => (CharPtr, &[CharPtr]),
        "fgets" => (CharPtr, &[CharPtr, Int, VoidPtr]),
        "RtlCopyMemory" | "CopyMemory" => (Void, &[VoidPtr, ConstVoidPtr, Size]),
        "read" => (SignedSize, &[Int, VoidPtr, Size]),
        "recv" => (Int, &[Int, VoidPtr, Size, Int]),
        "getenv" | "GetCommandLineA" => (CharPtr, &[]),
        "GetCommandLineW" => (WCharPtr, &[]),
        _ => return None,
    })
}

/// Summarize an internal function's return type without recursively invoking
/// the decompiler. Every returning block must trace its final RAX/EAX write to
/// the same known API return (possibly through another internal wrapper).
fn internal_return_type(an: &Analysis, bin: &Binary, name: &str) -> Option<CType> {
    let function = an.find_by_name(name)?;
    let mut visiting = BTreeSet::new();
    let mut memo = TypeMemo::default();
    return_type_summary(an, bin, function, &mut visiting, 0, &mut memo)
}

/// Answers the recursive type walks have already worked out.
///
/// Keyed by depth as well as address, because the walk gives up at a fixed
/// depth: what a function looks like with three levels of budget left is not
/// what it looks like with none, and one answer must not be served for the
/// other.
#[derive(Default)]
struct TypeMemo {
    ret: BTreeMap<(u64, usize), Option<CType>>,
    params: BTreeMap<(u64, usize), Option<Vec<CType>>>,
}

/// The return type a function's own code implies, remembering what it finds.
///
/// Both of these walks mark a function as being visited and unmark it on the
/// way out, so a function reached down two different call paths is walked
/// twice — and one reached N ways, 2^N times. At a depth limit of eight that is
/// not a slow analysis, it is a hang: `knife pseudo` on ucrtbase!sub_18000df50
/// never returned. The answer for a function at a given remaining depth cannot
/// change, so it is worked out once.
fn return_type_summary(
    an: &Analysis,
    bin: &Binary,
    function: &Function,
    visiting: &mut BTreeSet<u64>,
    depth: usize,
    memo: &mut TypeMemo,
) -> Option<CType> {
    let key = (function.addr, depth);
    if let Some(cached) = memo.ret.get(&key) {
        return *cached;
    }
    // A `None` that only means "already on this path" is about the path, not
    // about the function, and must not be remembered as if it were an answer.
    let on_this_path = visiting.contains(&function.addr);
    let answer = return_type_summary_inner(an, bin, function, visiting, depth, memo);
    if !on_this_path {
        memo.ret.insert(key, answer);
    }
    answer
}

fn return_type_summary_inner(
    an: &Analysis,
    bin: &Binary,
    function: &Function,
    visiting: &mut BTreeSet<u64>,
    depth: usize,
    memo: &mut TypeMemo,
) -> Option<CType> {
    if depth >= 8 || !visiting.insert(function.addr) {
        return None;
    }
    // The predecessor map, built once. It used to be rebuilt inside every step
    // of the backward walk by scanning every block in the function, which is a
    // second cost on top of the first and for the same reason: work that does
    // not depend on where the walk currently is.
    let index: BTreeMap<u64, usize> = function
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); function.blocks.len()];
    for (position, block) in function.blocks.iter().enumerate() {
        for successor in &block.succ {
            if let Some(&target) = index.get(successor) {
                predecessors[target].push(position);
            }
        }
    }
    let mut def_memo: BTreeMap<(usize, usize), DefType> = BTreeMap::new();

    let mut summary: Option<CType> = None;
    let mut saw_return = false;

    for (block_index, block) in function.blocks.iter().enumerate() {
        let is_return = block.insns.last().is_some_and(|raw| {
            decode(raw.bytes(), raw.addr, an.bits)
                .is_some_and(|instruction| instruction.mnemonic() == Mnemonic::Ret)
        });
        if !is_return {
            continue;
        }
        saw_return = true;
        let path_type = return_def_type(
            an,
            bin,
            function,
            block_index,
            block.insns.len().saturating_sub(1),
            visiting,
            depth,
            &predecessors,
            &mut def_memo,
            memo,
        );
        let Some(path_type) = path_type else {
            visiting.remove(&function.addr);
            return None;
        };
        summary = Some(match summary {
            None => path_type,
            Some(previous) => {
                let merged = previous.merge(path_type);
                if merged == CType::Unknown {
                    visiting.remove(&function.addr);
                    return None;
                }
                merged
            }
        });
    }
    visiting.remove(&function.addr);
    saw_return.then_some(summary).flatten()
}

#[allow(clippy::too_many_arguments)]
/// What the backward walk has worked out about one place in the function, or
/// that it is still working on it.
#[derive(Clone, Copy)]
enum DefType {
    /// On the current path already: a loop, and no answer down it.
    InProgress,
    Done(Option<CType>),
}

#[allow(clippy::too_many_arguments)]
fn return_def_type(
    an: &Analysis,
    bin: &Binary,
    function: &Function,
    block_index: usize,
    upto: usize,
    visiting: &mut BTreeSet<u64>,
    depth: usize,
    predecessors: &[Vec<usize>],
    def_memo: &mut BTreeMap<(usize, usize), DefType>,
    memo: &mut TypeMemo,
) -> Option<CType> {
    // Answer each place once. The walk used to carry a set of visited blocks
    // *per path*, cloning it at every predecessor, so a block reachable two ways
    // was explored twice and a block reachable N ways 2^N times. On a function
    // with a twelve-way switch in it that is not slow, it is a hang: `knife
    // pseudo` on ucrtbase!sub_18000df50 never returned at all.
    let key = (block_index, upto);
    match def_memo.get(&key) {
        Some(DefType::Done(answer)) => return *answer,
        Some(DefType::InProgress) => return None,
        None => def_memo.insert(key, DefType::InProgress),
    };
    let answer = return_def_type_uncached(
        an,
        bin,
        function,
        block_index,
        upto,
        visiting,
        depth,
        predecessors,
        def_memo,
        memo,
    );
    def_memo.insert(key, DefType::Done(answer));
    answer
}

#[allow(clippy::too_many_arguments)]
fn return_def_type_uncached(
    an: &Analysis,
    bin: &Binary,
    function: &Function,
    block_index: usize,
    upto: usize,
    visiting: &mut BTreeSet<u64>,
    depth: usize,
    predecessors: &[Vec<usize>],
    def_memo: &mut BTreeMap<(usize, usize), DefType>,
    memo: &mut TypeMemo,
) -> Option<CType> {
    let block = &function.blocks[block_index];
    let mut info = InstructionInfoFactory::new();
    for raw in block.insns[..upto.min(block.insns.len())].iter().rev() {
        let Some(instruction) = decode(raw.bytes(), raw.addr, an.bits) else {
            continue;
        };
        // A call defines RAX/EAX by ABI convention, not by an architectural
        // register effect encoded in the instruction. iced-x86 therefore does
        // not report the return register as written; model it explicitly.
        if instruction.mnemonic() == Mnemonic::Call {
            let called =
                raw.target_name.as_deref().map(strip_module).or_else(|| {
                    call_target(&instruction, an, bin).map(|target| an.label(target))
                })?;
            return prototype(&called).map(|prototype| prototype.0).or_else(|| {
                an.find_by_name(&called).and_then(|callee| {
                    return_type_summary(an, bin, callee, visiting, depth + 1, memo)
                })
            });
        }
        let writes_return = info.info(&instruction).used_registers().iter().any(|used| {
            used.register().is_gpr()
                && used.register().full_register() == Register::RAX
                && matches!(
                    used.access(),
                    OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite
                )
        });
        if !writes_return {
            continue;
        }
        return None;
    }

    let mut merged: Option<CType> = None;
    for &predecessor in &predecessors[block_index] {
        let ty = return_def_type(
            an,
            bin,
            function,
            predecessor,
            function.blocks[predecessor].insns.len(),
            visiting,
            depth,
            predecessors,
            def_memo,
            memo,
        )?;
        merged = Some(match merged {
            None => ty,
            Some(previous) => {
                let combined = previous.merge(ty);
                if combined == CType::Unknown {
                    return None;
                }
                combined
            }
        });
    }
    merged
}

fn internal_parameter_types(an: &Analysis, bin: &Binary, name: &str) -> Option<Vec<CType>> {
    let function = an.find_by_name(name)?;
    let mut visiting = BTreeSet::new();
    let mut memo = TypeMemo::default();
    parameter_type_summary(an, bin, function, &mut visiting, 0, &mut memo)
}

/// The parameter types a function's own code implies, remembering what it
/// finds. Same shape, and same reason, as `return_type_summary`.
fn parameter_type_summary(
    an: &Analysis,
    bin: &Binary,
    function: &Function,
    visiting: &mut BTreeSet<u64>,
    depth: usize,
    memo: &mut TypeMemo,
) -> Option<Vec<CType>> {
    let key = (function.addr, depth);
    if let Some(cached) = memo.params.get(&key) {
        return cached.clone();
    }
    let on_this_path = visiting.contains(&function.addr);
    let answer = parameter_type_summary_inner(an, bin, function, visiting, depth, memo);
    if !on_this_path {
        memo.params.insert(key, answer.clone());
    }
    answer
}

fn parameter_type_summary_inner(
    an: &Analysis,
    bin: &Binary,
    function: &Function,
    visiting: &mut BTreeSet<u64>,
    depth: usize,
    memo: &mut TypeMemo,
) -> Option<Vec<CType>> {
    if an.bits != 64 || depth >= 8 || !visiting.insert(function.addr) {
        return None;
    }
    let win64 = bin.format == Format::Pe;
    let abi = arg_registers(win64);
    let Some(arity) = internal_arity(an, function.addr, win64) else {
        visiting.remove(&function.addr);
        return None;
    };
    let index: BTreeMap<u64, usize> = function
        .blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); function.blocks.len()];
    for (position, block) in function.blocks.iter().enumerate() {
        for successor in &block.succ {
            if let Some(&target) = index.get(successor) {
                predecessors[target].push(position);
            }
        }
    }
    type Origins = BTreeMap<Register, BTreeSet<usize>>;
    let mut entry = vec![Origins::new(); function.blocks.len()];
    let mut exit = vec![Origins::new(); function.blocks.len()];
    let mut facts: Vec<Option<CType>> = vec![None; arity];
    let mut initial = Origins::new();
    for (position, register) in abi.iter().take(arity).enumerate() {
        initial.insert(*register, BTreeSet::from([position]));
    }

    let mut changed = true;
    let mut guard = 0usize;
    while changed && guard <= function.blocks.len().saturating_mul(abi.len() + 1) + 1 {
        changed = false;
        guard += 1;
        for (block_index, block) in function.blocks.iter().enumerate() {
            let mut incoming = Origins::new();
            if block.start == function.addr {
                merge_origins(&mut incoming, &initial);
            }
            for predecessor in &predecessors[block_index] {
                merge_origins(&mut incoming, &exit[*predecessor]);
            }
            if incoming != entry[block_index] {
                entry[block_index] = incoming.clone();
                changed = true;
            }
            let mut state = incoming;
            let mut info = InstructionInfoFactory::new();
            for raw in &block.insns {
                let Some(instruction) = decode(raw.bytes(), raw.addr, an.bits) else {
                    continue;
                };
                if instruction.mnemonic() == Mnemonic::Call {
                    let called = raw.target_name.as_deref().map(strip_module).or_else(|| {
                        call_target(&instruction, an, bin).map(|target| an.label(target))
                    });
                    if let Some(called) = called {
                        let expected = prototype(&called)
                            .map(|prototype| prototype.1.to_vec())
                            .or_else(|| {
                                an.find_by_name(&called).and_then(|callee| {
                                    parameter_type_summary(
                                        an,
                                        bin,
                                        callee,
                                        visiting,
                                        depth + 1,
                                        memo,
                                    )
                                })
                            })
                            .unwrap_or_default();
                        for (call_position, expected_type) in expected.into_iter().enumerate() {
                            if expected_type == CType::Unknown {
                                continue;
                            }
                            let Some(register) = abi.get(call_position) else {
                                break;
                            };
                            if let Some(origins) = state.get(register) {
                                for &origin in origins {
                                    merge_type_fact(&mut facts[origin], expected_type);
                                }
                            }
                        }
                    }
                    for register in abi {
                        state.remove(register);
                    }
                    state.remove(&Register::RAX);
                    continue;
                }

                if instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                {
                    let destination = instruction.op0_register().full_register();
                    let source = instruction.op1_register().full_register();
                    match state.get(&source).cloned() {
                        Some(origins) => {
                            state.insert(destination, origins);
                        }
                        None => {
                            state.remove(&destination);
                        }
                    }
                    continue;
                }
                let written: Vec<Register> = info
                    .info(&instruction)
                    .used_registers()
                    .iter()
                    .filter(|used| {
                        used.register().is_gpr()
                            && matches!(
                                used.access(),
                                OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite
                            )
                    })
                    .map(|used| used.register().full_register())
                    .collect();
                for register in written {
                    state.remove(&register);
                }
            }
            if state != exit[block_index] {
                exit[block_index] = state;
                changed = true;
            }
        }
    }
    visiting.remove(&function.addr);
    Some(
        facts
            .into_iter()
            .map(|fact| fact.unwrap_or(CType::Unknown))
            .collect(),
    )
}

fn merge_origins(
    destination: &mut BTreeMap<Register, BTreeSet<usize>>,
    source: &BTreeMap<Register, BTreeSet<usize>>,
) {
    for (register, origins) in source {
        destination
            .entry(*register)
            .or_default()
            .extend(origins.iter().copied());
    }
}

fn merge_type_fact(fact: &mut Option<CType>, incoming: CType) {
    *fact = Some(match *fact {
        None => incoming,
        Some(CType::Unknown) => CType::Unknown,
        Some(previous) => previous.merge(incoming),
    });
}

#[derive(Clone, Copy)]
struct TypeCx<'a> {
    strings: &'a BTreeMap<u64, Located>,
    an: &'a Analysis,
    bin: &'a Binary,
    db: &'a Db,
    function: u64,
}

fn field_type_fact(address: &Expr, cx: TypeCx<'_>) -> Option<CType> {
    let Expr::Bin(op @ ("+" | "-"), base, offset) = address else {
        return None;
    };
    let Expr::Const(offset) = offset.as_ref() else {
        return None;
    };
    if !simple_field_base(base) || *offset == 0 {
        return None;
    }
    let signed = i64::try_from(*offset).ok().and_then(|offset| {
        if *op == "-" {
            offset.checked_neg()
        } else {
            Some(offset)
        }
    })?;
    let identity = field_base_identity(
        base,
        Rx {
            an: cx.an,
            strings: cx.strings,
            db: cx.db,
            function: cx.function,
        },
    )?;
    let type_name = cx.db.bound_type(cx.function, &identity)?;
    let data_type = cx
        .db
        .fields
        .get(type_name)?
        .get(&signed)?
        .data_type
        .as_deref()?;
    Some(user_type_fact(data_type))
}

fn expr_type(e: &Expr, cx: TypeCx<'_>, return_cache: &mut BTreeMap<String, CType>) -> CType {
    match e {
        Expr::Const(v) if cx.strings.contains_key(v) => CType::ConstCharPtr,
        Expr::Addr(_) => CType::VoidPtr,
        Expr::Mem(address) => field_type_fact(address, cx).unwrap_or(CType::Unknown),
        Expr::Call(name, _) => stored_prototype(cx.an, cx.db, name)
            .map(|prototype| user_type_fact(&prototype.returns))
            .or_else(|| prototype(name).map(|prototype| prototype.0))
            .unwrap_or_else(|| {
                if let Some(cached) = return_cache.get(name) {
                    return *cached;
                }
                let recovered = internal_return_type(cx.an, cx.bin, name).unwrap_or(CType::Unknown);
                return_cache.insert(name.clone(), recovered);
                recovered
            }),
        Expr::Bin(op, _, _) if matches!(*op, "==" | "!=" | "<" | "<=" | ">" | ">=") => CType::Bool,
        Expr::Ternary(_, a, b) => {
            expr_type(a, cx, return_cache).merge(expr_type(b, cx, return_cache))
        }
        Expr::Phi(_, values) => values.iter().fold(CType::Unknown, |ty, value| {
            ty.merge(expr_type(value, cx, return_cache))
        }),
        _ => CType::Unknown,
    }
}

/// Local-storage classification does not need call-graph context. Keep this
/// small variant for synthetic IR tests and for facts that are authoritative
/// without resolving an internal callee.
fn expr_type_shallow(e: &Expr, strings: &BTreeMap<u64, Located>) -> CType {
    match e {
        Expr::Const(v) if strings.contains_key(v) => CType::ConstCharPtr,
        Expr::Addr(_) => CType::VoidPtr,
        Expr::Call(name, _) => prototype(name).map_or(CType::Unknown, |prototype| prototype.0),
        Expr::Bin(op, _, _) if matches!(*op, "==" | "!=" | "<" | "<=" | ">" | ">=") => CType::Bool,
        Expr::Ternary(_, a, b) => {
            expr_type_shallow(a, strings).merge(expr_type_shallow(b, strings))
        }
        Expr::Phi(_, values) => values.iter().fold(CType::Unknown, |ty, value| {
            ty.merge(expr_type_shallow(value, strings))
        }),
        _ => CType::Unknown,
    }
}

fn expr_type_with_regs(
    e: &Expr,
    regs: &BTreeMap<Register, CType>,
    cx: TypeCx<'_>,
    return_cache: &mut BTreeMap<String, CType>,
) -> CType {
    match e {
        Expr::Reg(root, _) => regs.get(root).copied().unwrap_or(CType::Unknown),
        _ => expr_type(e, cx, return_cache),
    }
}

fn params_in(e: &Expr, out: &mut BTreeSet<Param>) {
    match e {
        Expr::Reg(root, _) => {
            out.insert(Param::Reg(*root));
        }
        Expr::Mem(a) if matches!(a.as_ref(), Expr::Stack(off) if *off > 0) => {
            if let Expr::Stack(off) = a.as_ref() {
                out.insert(Param::Stack(*off));
            }
        }
        Expr::Mem(a) | Expr::Addr(a) => params_in(a, out),
        Expr::Bin(_, a, b) => {
            params_in(a, out);
            params_in(b, out);
        }
        Expr::Phi(_, values) => values.iter().for_each(|value| params_in(value, out)),
        Expr::Ternary(c, a, b) => {
            params_in(c, out);
            params_in(a, out);
            params_in(b, out);
        }
        Expr::Call(_, args) => args.iter().for_each(|arg| params_in(arg, out)),
        _ => {}
    }
}

fn address_base_register(e: &Expr) -> Option<Register> {
    match e {
        Expr::Reg(root, _) => Some(*root),
        Expr::Bin("+" | "-", base, _) => address_base_register(base),
        _ => None,
    }
}

fn pointer_params_in(e: &Expr, facts: &mut BTreeMap<Param, CType>) {
    if let Expr::Mem(address) = e {
        if let Some(reg) = address_base_register(address) {
            let param = Param::Reg(reg);
            let old = facts.get(&param).copied().unwrap_or(CType::Unknown);
            facts.insert(param, old.merge(CType::VoidPtr));
        }
    }
    match e {
        Expr::Mem(a) | Expr::Addr(a) | Expr::Un(_, a) => pointer_params_in(a, facts),
        Expr::Bin(_, a, b) => {
            pointer_params_in(a, facts);
            pointer_params_in(b, facts);
        }
        Expr::Phi(_, values) => values
            .iter()
            .for_each(|value| pointer_params_in(value, facts)),
        Expr::Ternary(c, a, b) => {
            pointer_params_in(c, facts);
            pointer_params_in(a, facts);
            pointer_params_in(b, facts);
        }
        Expr::Call(_, args) => args.iter().for_each(|arg| pointer_params_in(arg, facts)),
        Expr::Const(_) | Expr::Reg(..) | Expr::Stack(_) | Expr::Global(_) | Expr::Opaque(_) => {}
    }
}

fn visit_stmt_exprs(s: &Stmt, mut visit: impl FnMut(&Expr)) {
    match s {
        Stmt::Set(_, src) => visit(src),
        Stmt::CallVoid(e) | Stmt::Ret(Some(e)) | Stmt::Branch(e, _) | Stmt::Switch(e) => visit(e),
        Stmt::Ret(None) | Stmt::Goto(_) | Stmt::Asm { .. } => {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalKind {
    Scalar(CType),
    Bytes,
    Chars,
    WideChars,
}

impl LocalKind {
    fn merge(self, other: Self) -> Self {
        use LocalKind::*;
        match (self, other) {
            (a, b) if a == b => a,
            (Scalar(a), Scalar(b)) => Scalar(a.merge(b)),
            (Chars, Chars) => Chars,
            (WideChars, WideChars) => WideChars,
            // Addressed storage with incompatible pointee evidence remains raw
            // bytes. That is less specific, but never invents a character width.
            _ => Bytes,
        }
    }

    fn declaration(self, off: i64, bound_type: Option<&str>, alias: Option<&str>) -> String {
        let recovered = slot_name(off);
        let name = alias.unwrap_or(&recovered);
        if let Some(type_name) = bound_type {
            return format!("{type_name} * {name};");
        }
        match self {
            Self::Scalar(ty) => format!("{} {name};", ty.c()),
            Self::Bytes => format!("uint8_t {name}[]; /* extent unresolved */"),
            Self::Chars => format!("char {name}[]; /* extent unresolved */"),
            Self::WideChars => format!("wchar_t {name}[]; /* extent unresolved */"),
        }
    }
}

fn local_kind_for_pointer(expected: Option<CType>) -> LocalKind {
    match expected {
        Some(CType::CharPtr | CType::ConstCharPtr) => LocalKind::Chars,
        Some(CType::WCharPtr | CType::ConstWCharPtr) => LocalKind::WideChars,
        _ => LocalKind::Bytes,
    }
}

fn record_local(locals: &mut BTreeMap<i64, LocalKind>, off: i64, kind: LocalKind) {
    if off >= 0 {
        return;
    }
    locals
        .entry(off)
        .and_modify(|old| *old = old.merge(kind))
        .or_insert(kind);
}

fn locals_in_expr(
    e: &Expr,
    expected: Option<CType>,
    strings: &BTreeMap<u64, Located>,
    locals: &mut BTreeMap<i64, LocalKind>,
    context: Option<(&Analysis, &Binary, &Db)>,
    parameter_cache: &mut BTreeMap<String, Option<Vec<CType>>>,
) {
    match e {
        Expr::Addr(a) if matches!(a.as_ref(), Expr::Stack(off) if *off < 0) => {
            if let Expr::Stack(off) = a.as_ref() {
                record_local(locals, *off, local_kind_for_pointer(expected));
            }
        }
        Expr::Mem(a) if matches!(a.as_ref(), Expr::Stack(off) if *off < 0) => {
            if let Expr::Stack(off) = a.as_ref() {
                record_local(
                    locals,
                    *off,
                    LocalKind::Scalar(expected.unwrap_or(CType::Unknown)),
                );
            }
        }
        Expr::Call(name, args) => {
            let expected_args = context
                .and_then(|(an, _, db)| stored_prototype(an, db, name))
                .map(|prototype| {
                    prototype
                        .params
                        .iter()
                        .map(|param| user_type_fact(param))
                        .collect()
                })
                .or_else(|| prototype(name).map(|prototype| prototype.1.to_vec()))
                .or_else(|| {
                    context.and_then(|(an, bin, _)| {
                        parameter_cache
                            .entry(name.clone())
                            .or_insert_with(|| internal_parameter_types(an, bin, name))
                            .clone()
                    })
                })
                .unwrap_or_default();
            for (index, arg) in args.iter().enumerate() {
                locals_in_expr(
                    arg,
                    expected_args.get(index).copied(),
                    strings,
                    locals,
                    context,
                    parameter_cache,
                );
            }
        }
        Expr::Mem(a) => locals_in_expr(
            a,
            Some(CType::VoidPtr),
            strings,
            locals,
            context,
            parameter_cache,
        ),
        Expr::Addr(a) | Expr::Un(_, a) => {
            locals_in_expr(a, expected, strings, locals, context, parameter_cache)
        }
        Expr::Bin(_, a, b) => {
            locals_in_expr(a, expected, strings, locals, context, parameter_cache);
            locals_in_expr(b, expected, strings, locals, context, parameter_cache);
        }
        Expr::Phi(_, values) => {
            for value in values {
                locals_in_expr(value, expected, strings, locals, context, parameter_cache);
            }
        }
        Expr::Ternary(c, a, b) => {
            locals_in_expr(
                c,
                Some(CType::Bool),
                strings,
                locals,
                context,
                parameter_cache,
            );
            locals_in_expr(a, expected, strings, locals, context, parameter_cache);
            locals_in_expr(b, expected, strings, locals, context, parameter_cache);
        }
        Expr::Const(_) | Expr::Reg(..) | Expr::Stack(_) | Expr::Global(_) | Expr::Opaque(_) => {
            let _ = strings;
        }
    }
}

#[cfg(test)]
fn local_declarations(
    blocks: &[IrBlock],
    strings: &BTreeMap<u64, Located>,
    db: &Db,
    function: u64,
) -> Vec<String> {
    local_declarations_impl(blocks, strings, db, function, None)
}

fn local_declarations_with_context(
    blocks: &[IrBlock],
    strings: &BTreeMap<u64, Located>,
    db: &Db,
    function: u64,
    an: &Analysis,
    bin: &Binary,
) -> Vec<String> {
    local_declarations_impl(blocks, strings, db, function, Some((an, bin, db)))
}

fn local_declarations_impl(
    blocks: &[IrBlock],
    strings: &BTreeMap<u64, Located>,
    db: &Db,
    function: u64,
    context: Option<(&Analysis, &Binary, &Db)>,
) -> Vec<String> {
    let mut locals = BTreeMap::new();
    let mut parameter_cache = BTreeMap::new();
    for block in blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Set(dst, src) => {
                    if let Expr::Mem(a) = dst {
                        if let Expr::Stack(off) = a.as_ref() {
                            record_local(
                                &mut locals,
                                *off,
                                LocalKind::Scalar(expr_type_shallow(src, strings)),
                            );
                        }
                    }
                    locals_in_expr(
                        dst,
                        None,
                        strings,
                        &mut locals,
                        context,
                        &mut parameter_cache,
                    );
                    locals_in_expr(
                        src,
                        None,
                        strings,
                        &mut locals,
                        context,
                        &mut parameter_cache,
                    );
                }
                Stmt::CallVoid(e) | Stmt::Ret(Some(e)) | Stmt::Branch(e, _) | Stmt::Switch(e) => {
                    locals_in_expr(e, None, strings, &mut locals, context, &mut parameter_cache)
                }
                Stmt::Ret(None) | Stmt::Goto(_) | Stmt::Asm { .. } => {}
            }
        }
    }
    locals
        .into_iter()
        .map(|(off, kind)| {
            let base = slot_name(off);
            kind.declaration(
                off,
                db.bound_type(function, &base),
                db.variable_name(function, &base),
            )
        })
        .collect()
}

fn function_signature(
    an: &Analysis,
    bin: &Binary,
    f: &Function,
    blocks: &[IrBlock],
    strings: &BTreeMap<u64, Located>,
    db: &Db,
) -> String {
    let function = f.addr.wrapping_sub(an.display_base);
    let abi_regs: &[Register] = if an.bits == 32 {
        &[]
    } else if bin.format == Format::Pe {
        &[Register::RCX, Register::RDX, Register::R8, Register::R9]
    } else {
        &[
            Register::RDI,
            Register::RSI,
            Register::RDX,
            Register::RCX,
            Register::R8,
            Register::R9,
        ]
    };
    let mut found = BTreeSet::new();
    let mut facts: BTreeMap<Param, CType> = BTreeMap::new();
    let mut ret = CType::Void;
    let mut has_value_return = false;
    let mut value_regs: BTreeMap<Register, CType> = BTreeMap::new();
    let mut return_cache = BTreeMap::new();
    let mut parameter_cache: BTreeMap<String, Option<Vec<CType>>> = BTreeMap::new();
    let type_cx = TypeCx {
        strings,
        an,
        bin,
        db,
        function,
    };

    // Recover register value types first. Merging all assignments is
    // conservative across branches and register reuse: disagreement drops back
    // to uintptr_t rather than choosing whichever assignment was visited last.
    for block in blocks {
        for stmt in &block.stmts {
            if let Stmt::Set(Expr::Reg(root, _), src) = stmt {
                let ty = expr_type_with_regs(src, &value_regs, type_cx, &mut return_cache);
                let old = value_regs.get(root).copied().unwrap_or(CType::Unknown);
                value_regs.insert(*root, old.merge(ty));
            }
        }
    }

    for block in blocks {
        for stmt in &block.stmts {
            visit_stmt_exprs(stmt, |e| {
                params_in(e, &mut found);
                pointer_params_in(e, &mut facts);
                if let Expr::Call(name, args) = e {
                    let expected = stored_prototype(an, db, name)
                        .map(|prototype| {
                            prototype
                                .params
                                .iter()
                                .map(|param| user_type_fact(param))
                                .collect()
                        })
                        .or_else(|| prototype(name).map(|prototype| prototype.1.to_vec()))
                        .or_else(|| {
                            parameter_cache
                                .entry(name.clone())
                                .or_insert_with(|| internal_parameter_types(an, bin, name))
                                .clone()
                        });
                    if let Some(expected) = expected {
                        for (arg, ty) in args.iter().zip(&expected) {
                            let mut used = BTreeSet::new();
                            params_in(arg, &mut used);
                            for param in used {
                                let old = facts.get(&param).copied().unwrap_or(CType::Unknown);
                                facts.insert(param, old.merge(*ty));
                            }
                        }
                    }
                }
            });
            if let Stmt::Ret(Some(value)) = stmt {
                let ty = expr_type_with_regs(value, &value_regs, type_cx, &mut return_cache);
                ret = if has_value_return { ret.merge(ty) } else { ty };
                has_value_return = true;
            }
        }
    }
    if has_value_return && ret == CType::Void {
        ret = CType::Unknown;
    }
    found.retain(|param| match param {
        Param::Reg(reg) => abi_regs.contains(reg),
        Param::Stack(_) => an.bits == 32,
    });

    let mut ordered = Vec::new();
    for reg in abi_regs {
        let param = Param::Reg(*reg);
        if found.remove(&param) {
            ordered.push(param);
        }
    }
    ordered.extend(found);
    let name = if f.name.is_empty() {
        format!("sub_{:x}", f.addr + an.display_base)
    } else {
        f.name.clone()
    };
    if let Some(prototype) = db.prototype(function) {
        let params = prototype
            .params
            .iter()
            .enumerate()
            .map(|(index, ty)| {
                let recovered = if let Some(register) = abi_regs.get(index) {
                    format!("{register:?}").to_lowercase()
                } else if an.bits == 32 {
                    slot_name(((index + 1) * 4) as i64)
                } else {
                    format!("arg_{}", index + 1)
                };
                let param_name = db.variable_name(function, &recovered).unwrap_or(&recovered);
                format!("{ty} {param_name}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!("{} {}({params}) {{", prototype.returns, name);
    }
    let args: Vec<String> = ordered
        .into_iter()
        .map(|param| {
            let recovered = match param {
                Param::Reg(reg) => format!("{reg:?}").to_lowercase(),
                Param::Stack(off) => slot_name(off),
            };
            let name = db
                .variable_name(function, &recovered)
                .unwrap_or(&recovered)
                .to_string();
            let ty = db
                .bound_type(function, &recovered)
                .map(|type_name| format!("{type_name} *"))
                .unwrap_or_else(|| {
                    facts
                        .get(&param)
                        .copied()
                        .unwrap_or(CType::Unknown)
                        .c()
                        .to_string()
                });
            format!("{ty} {name}")
        })
        .collect();
    format!("{} {}({}) {{", ret.c(), name, args.join(", "))
}

fn render(
    an: &Analysis,
    bin: &Binary,
    f: &Function,
    blocks: &[IrBlock],
    strings: &BTreeMap<u64, Located>,
    db: &Db,
) -> Vec<Line> {
    let function = f.addr.wrapping_sub(an.display_base);
    let r = Rx {
        an,
        strings,
        db,
        function,
    };
    let base = an.display_base;
    let mut out = vec![Line {
        label: true,
        text: function_signature(an, bin, f, blocks, strings, db),
    }];
    out.extend(
        local_declarations_with_context(blocks, strings, db, function, an, bin)
            .into_iter()
            .map(|text| Line { label: false, text }),
    );
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            out.push(Line {
                label: true,
                text: format!("loc_{:x}:", b.start + base),
            });
        }
        for s in &b.stmts {
            out.push(Line {
                label: false,
                text: render_stmt(s, base, r),
            });
        }
    }
    out.push(Line {
        label: true,
        text: "}".to_string(),
    });
    out
}

// ── control-flow structuring ────────────────────────────────────────────────
//
// The flat rendering above is always correct but reads as goto spaghetti. This
// recovers `if`/`else` and `while` from the control-flow graph so it reads like
// C. The contract is strict: it emits a structured form only for flow it can
// prove reconverges (via post-dominators for conditionals and dominators for
// loops), and returns `None` on anything else, so the caller falls back to the
// flat form. A wrong structure would be worse than a plain goto, so it never
// guesses.

/// A block's terminator, over block indices.
#[derive(Debug)]
enum Term {
    Ret,
    Goto(usize),
    Fall(usize),
    Cond {
        cond: Expr,
        taken: usize,
        fall: usize,
    },
    /// An indexed jump: a selector and the case target blocks (deduplicated, in
    /// the successor order the engine resolved from the jump table).
    Switch {
        sel: Expr,
        cases: Vec<usize>,
    },
    End,
}

struct Cfg {
    body: Vec<Vec<Stmt>>,
    term: Vec<Term>,
    succ: Vec<Vec<usize>>,
    /// The virtual address each node starts at, for labels and `goto` targets.
    start: Vec<u64>,
}

fn build_cfg(blocks: &[IrBlock]) -> Cfg {
    let idx: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start, i))
        .collect();
    let n = blocks.len();
    let mut body = Vec::with_capacity(n);
    let mut term = Vec::with_capacity(n);
    for (i, b) in blocks.iter().enumerate() {
        let mut stmts = b.stmts.clone();
        let next = (i + 1 < n).then_some(i + 1);
        // The trailing branch/goto becomes the terminator; it is popped from the
        // body only when its target is a block we can place. When it is not (an
        // out-of-function jump), it stays in the body and renders verbatim, so no
        // control transfer is ever silently lost.
        let t = match stmts.last() {
            Some(Stmt::Ret(_)) => Term::Ret,
            Some(Stmt::Goto(a)) => match idx.get(a) {
                Some(&j) => {
                    stmts.pop();
                    Term::Goto(j)
                }
                None => Term::End,
            },
            Some(Stmt::Branch(cond, a)) => {
                let (cond, a) = (cond.clone(), *a);
                match (idx.get(&a), next) {
                    (Some(&taken), Some(fall)) => {
                        stmts.pop();
                        Term::Cond { cond, taken, fall }
                    }
                    _ => Term::End,
                }
            }
            // An indexed jump: the case targets are the block's engine-resolved
            // successors (the jump table), deduplicated in address order.
            Some(Stmt::Switch(sel)) => {
                let sel = sel.clone();
                let mut cases: Vec<usize> = Vec::new();
                for s in &b.succ {
                    if let Some(&j) = idx.get(s) {
                        if !cases.contains(&j) {
                            cases.push(j);
                        }
                    }
                }
                if cases.is_empty() {
                    Term::End
                } else {
                    stmts.pop();
                    Term::Switch { sel, cases }
                }
            }
            _ => next.map(Term::Fall).unwrap_or(Term::End),
        };
        body.push(stmts);
        term.push(t);
    }
    let succ = term
        .iter()
        .map(|t| match t {
            Term::Goto(a) | Term::Fall(a) => vec![*a],
            Term::Cond { taken, fall, .. } => vec![*taken, *fall],
            Term::Switch { cases, .. } => cases.clone(),
            Term::Ret | Term::End => vec![],
        })
        .collect();
    let start = blocks.iter().map(|b| b.start).collect();
    Cfg {
        body,
        term,
        succ,
        start,
    }
}

/// Reverse postorder from `entry`, and each node's position in it.
fn reverse_postorder(succ: &[Vec<usize>], entry: usize) -> Vec<usize> {
    let n = succ.len();
    let mut seen = vec![false; n];
    let mut post = Vec::new();
    // Iterative DFS to avoid deep recursion on large functions.
    let mut stack = vec![(entry, 0usize)];
    seen[entry] = true;
    while let Some((node, ci)) = stack.pop() {
        if ci < succ[node].len() {
            stack.push((node, ci + 1));
            let s = succ[node][ci];
            if !seen[s] {
                seen[s] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(node);
        }
    }
    post.reverse();
    post
}

/// Immediate dominators (Cooper-Harvey-Kennedy). `idom[entry] == entry`.
fn dominators(succ: &[Vec<usize>], entry: usize) -> Vec<usize> {
    let n = succ.len();
    let rpo = reverse_postorder(succ, entry);
    let mut order = vec![usize::MAX; n];
    for (i, &b) in rpo.iter().enumerate() {
        order[b] = i;
    }
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (u, ss) in succ.iter().enumerate() {
        for &v in ss {
            preds[v].push(u);
        }
    }
    let mut idom = vec![usize::MAX; n];
    idom[entry] = entry;
    let intersect = |mut a: usize, mut b: usize, idom: &[usize], order: &[usize]| {
        while a != b {
            while order[a] > order[b] {
                a = idom[a];
            }
            while order[b] > order[a] {
                b = idom[b];
            }
        }
        a
    };
    loop {
        let mut changed = false;
        for &b in rpo.iter() {
            if b == entry {
                continue;
            }
            let mut new = usize::MAX;
            for &p in &preds[b] {
                if idom[p] == usize::MAX {
                    continue;
                }
                new = if new == usize::MAX {
                    p
                } else {
                    intersect(p, new, &idom, &order)
                };
            }
            if new != usize::MAX && idom[b] != new {
                idom[b] = new;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    idom
}

/// Immediate post-dominators. A virtual exit (index `n`) collects every
/// returning or terminal block; post-dominators are the dominators of the
/// reversed graph from that exit. `ipdom[b] >= n` means no real block
/// post-dominates `b` (it reaches the function exit directly).
fn post_dominators(cfg: &Cfg) -> Vec<usize> {
    let n = cfg.succ.len();
    let mut rsucc: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
    for (u, ss) in cfg.succ.iter().enumerate() {
        for &v in ss {
            rsucc[v].push(u); // reversed edge
        }
    }
    for (i, t) in cfg.term.iter().enumerate() {
        if matches!(t, Term::Ret | Term::End) || cfg.succ[i].is_empty() {
            rsucc[n].push(i);
        }
    }
    let idom_r = dominators(&rsucc, n);
    idom_r[..n].to_vec()
}

/// Does `a` dominate `b`?
fn dominates(a: usize, b: usize, idom: &[usize]) -> bool {
    let mut x = b;
    loop {
        if x == a {
            return true;
        }
        if x == 0 || idom[x] == usize::MAX {
            return a == 0 && b != usize::MAX;
        }
        if idom[x] == x {
            return false;
        }
        x = idom[x];
    }
}

/// Render the function as structured C. The reducible skeleton becomes nested
/// `if`/`else` and `while`; the handful of edges that break nesting (shared
/// join blocks in a `switch`, a jump into a common tail) become an explicit
/// `goto` to a labelled block. Every node is emitted exactly once, so the
/// control flow is preserved exactly: this is a faithful rendering, not a guess.
/// Returns `None` only when the graph is not amenable at all (an unreachable
/// block, or an empty function).
fn structure(
    an: &Analysis,
    bin: &Binary,
    f: &Function,
    blocks: &[IrBlock],
    strings: &BTreeMap<u64, Located>,
    db: &Db,
) -> Option<Vec<Line>> {
    let function = f.addr.wrapping_sub(an.display_base);
    let r = Rx {
        an,
        strings,
        db,
        function,
    };
    let cfg = build_cfg(blocks);
    let n = cfg.body.len();
    if n == 0 {
        return None;
    }
    let idom = dominators(&cfg.succ, 0);
    // Every node must be reachable from entry; an unreachable block means the
    // recovered graph is inconsistent, so leave it to the flat form.
    if (1..n).any(|i| idom[i] == usize::MAX) {
        return None;
    }
    let ipdom = post_dominators(&cfg);

    // A back edge (u -> h with h dominating u) marks h as a loop header and u as
    // one of its latches. A header may have several latches; they all belong to
    // the one loop.
    let mut latches: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (u, ss) in cfg.succ.iter().enumerate() {
        for &v in ss {
            if dominates(v, u, &idom) {
                latches.entry(v).or_default().push(u);
            }
        }
    }
    let headers: BTreeSet<usize> = latches.keys().copied().collect();

    // The node set of each natural loop, so `emit_loop` can tell the edge that
    // stays in the loop from the one that leaves it. Dominance alone cannot: a
    // loop's only exit block is still dominated by the header. The natural loop
    // of a back edge (latch -> header) is the header plus every node that can
    // reach a latch without passing through the header.
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (u, ss) in cfg.succ.iter().enumerate() {
        for &v in ss {
            preds[v].push(u);
        }
    }
    let mut loop_body: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (&h, ls) in &latches {
        let mut body: BTreeSet<usize> = BTreeSet::new();
        body.insert(h);
        let mut work = ls.clone();
        while let Some(x) = work.pop() {
            if body.insert(x) {
                work.extend_from_slice(&preds[x]);
            }
        }
        loop_body.insert(h, body);
    }

    let base = an.display_base;
    let mut out = Ir {
        cfg: &cfg,
        ipdom: &ipdom,
        loops: &headers,
        loop_body: &loop_body,
        r,
        base,
        lines: Vec::new(),
        emitted: vec![false; n],
        node_line: vec![usize::MAX; n],
        node_indent: vec![1; n],
        label_needed: BTreeSet::new(),
    };
    out.lines.push(Line {
        label: true,
        text: function_signature(an, bin, f, blocks, strings, db),
    });
    out.lines.extend(
        local_declarations_with_context(blocks, strings, db, function, an, bin)
            .into_iter()
            .map(|text| Line {
                label: false,
                text: format!("    {text}"),
            }),
    );
    out.emit(0, None, None, 1);
    out.lines.push(Line {
        label: true,
        text: "}".to_string(),
    });

    // Insert a label before each block a `goto` targets. Done back to front so
    // earlier insertions do not shift the positions still to come.
    let mut labels: Vec<(usize, usize, u64)> = out
        .label_needed
        .iter()
        .filter(|&&nd| out.node_line[nd] != usize::MAX)
        .map(|&nd| (out.node_line[nd], out.node_indent[nd], cfg.start[nd] + base))
        .collect();
    labels.sort_by_key(|&(at, ..)| std::cmp::Reverse(at));
    for (at, indent, addr) in labels {
        out.lines.insert(
            at,
            Line {
                label: true,
                text: format!("{}loc_{addr:x}:", "    ".repeat(indent - 1)),
            },
        );
    }
    Some(out.lines)
}

struct Ir<'a> {
    cfg: &'a Cfg,
    ipdom: &'a [usize],
    /// Loop headers.
    loops: &'a BTreeSet<usize>,
    loop_body: &'a BTreeMap<usize, BTreeSet<usize>>,
    r: Rx<'a>,
    base: u64,
    lines: Vec<Line>,
    emitted: Vec<bool>,
    /// The line index at which each node's first statement was emitted, so a
    /// label can be inserted there afterwards. `usize::MAX` until emitted.
    node_line: Vec<usize>,
    /// The indent each node was emitted at, so its label lines up with it.
    node_indent: Vec<usize>,
    /// Blocks that a `goto` jumps to and therefore need a label.
    label_needed: BTreeSet<usize>,
}

impl Ir<'_> {
    fn push(&mut self, indent: usize, text: String) {
        self.lines.push(Line {
            label: false,
            text: format!("{}{}", "    ".repeat(indent - 1), text),
        });
    }

    /// Emit a `goto` to an already-placed block, recording that the block needs
    /// a label.
    fn emit_goto(&mut self, indent: usize, target: usize) {
        self.label_needed.insert(target);
        let addr = self.cfg.start[target] + self.base;
        self.push(indent, format!("goto loc_{addr:x};"));
    }

    /// If `h` is a `while`-shaped header (a conditional with exactly one edge
    /// inside the loop body and one leaving it), return the loop test, the body
    /// entry, and the follow block. The test is negated when the loop is entered
    /// on the fall edge, so `while (cond)` always means "stay in the loop".
    fn while_shape(&self, h: usize) -> Option<(Expr, usize, usize)> {
        let Term::Cond { cond, taken, fall } = &self.cfg.term[h] else {
            return None;
        };
        let (taken, fall) = (*taken, *fall);
        let body = self.loop_body.get(&h)?;
        match (body.contains(&taken), body.contains(&fall)) {
            (true, false) => Some((cond.clone(), taken, fall)),
            (false, true) => Some((not(cond, self.r), fall, taken)),
            _ => None,
        }
    }

    /// Emit the region starting at `n`, stopping before `stop`, inside an
    /// optional enclosing loop `(header, follow)`. Each block is emitted exactly
    /// once; an edge that cannot be a fall-through, a `break`, or a `continue`
    /// becomes a `goto`, so the flow is always preserved.
    fn emit(
        &mut self,
        mut n: usize,
        stop: Option<usize>,
        loopc: Option<(usize, usize)>,
        indent: usize,
    ) {
        loop {
            if Some(n) == stop {
                return;
            }
            if let Some((hdr, follow)) = loopc {
                // Leaving or re-entering the enclosing loop is a `break` /
                // `continue`, not a jump to a placed block.
                if n == follow {
                    self.push(indent, "break;".into());
                    return;
                }
                if n == hdr {
                    self.push(indent, "continue;".into());
                    return;
                }
            }
            if self.emitted[n] {
                self.emit_goto(indent, n);
                return;
            }

            // A `while`-shaped loop header we are entering (not the enclosing
            // one) becomes a `while`. A header of any other shape falls through
            // to ordinary emission, and its back edges render as `goto`.
            if self.loops.contains(&n) && loopc.map(|c| c.0) != Some(n) {
                if let Some(shape) = self.while_shape(n) {
                    n = self.emit_loop(n, shape, indent);
                    continue;
                }
            }

            self.node_line[n] = self.lines.len();
            self.node_indent[n] = indent;
            self.emitted[n] = true;
            for s in &self.cfg.body[n] {
                self.push(indent, render_stmt(s, self.base, self.r));
            }

            match &self.cfg.term[n] {
                // The `return ...;` (or a verbatim out-of-function jump) is
                // already in this block's body, so the path ends here.
                Term::Ret | Term::End => return,
                Term::Goto(t) | Term::Fall(t) => n = *t,
                Term::Cond { cond, taken, fall } => {
                    let (cond, taken, fall) = (cond.clone(), *taken, *fall);
                    match self.emit_if(n, cond, taken, fall, stop, loopc, indent) {
                        Some(follow) => n = follow,
                        None => return,
                    }
                }
                Term::Switch { sel, cases } => {
                    let (sel, cases) = (sel.clone(), cases.clone());
                    match self.emit_switch(n, sel, cases, stop, loopc, indent) {
                        Some(follow) => n = follow,
                        None => return,
                    }
                }
            }
        }
    }

    /// Emit an `if`/`else` whose branches reconverge at the conditional's
    /// immediate post-dominator, and return that follow block to continue from.
    /// `None` means both arms terminate (a `return` or `break` on each side), so
    /// there is nothing after the `if`.
    #[allow(clippy::too_many_arguments)]
    fn emit_if(
        &mut self,
        node: usize,
        cond: Expr,
        taken: usize,
        fall: usize,
        stop: Option<usize>,
        loopc: Option<(usize, usize)>,
        indent: usize,
    ) -> Option<usize> {
        // The reconvergence point of the two arms is the conditional's immediate
        // post-dominator. If it has none inside the function (both arms end in a
        // return, say), the arms run to their own ends.
        let n_nodes = self.cfg.body.len();
        let ipd = self.ipdom.get(node).copied().unwrap_or(usize::MAX);
        let follow = (ipd < n_nodes).then_some(ipd);
        let arm_stop = follow.or(stop);
        let is_follow = |arm: usize| Some(arm) == follow;

        // When an arm target is the follow, that arm is empty and the code
        // simply continues after the `if`; otherwise the arm has a body.
        match (is_follow(taken), is_follow(fall)) {
            (false, true) => {
                self.push(indent, format!("if ({}) {{", render_expr(&cond, self.r)));
                self.emit(taken, arm_stop, loopc, indent + 1);
                self.push(indent, "}".into());
            }
            (true, false) => {
                self.push(
                    indent,
                    format!("if ({}) {{", render_expr(&not(&cond, self.r), self.r)),
                );
                self.emit(fall, arm_stop, loopc, indent + 1);
                self.push(indent, "}".into());
            }
            (false, false) => {
                self.push(indent, format!("if ({}) {{", render_expr(&cond, self.r)));
                self.emit(taken, arm_stop, loopc, indent + 1);
                self.push(indent, "} else {".into());
                self.emit(fall, arm_stop, loopc, indent + 1);
                self.push(indent, "}".into());
            }
            // Both arms are the follow: the branch has no observable effect on
            // structure, so continue at the follow.
            (true, true) => {}
        }
        follow
    }

    /// Emit a `switch` for an indexed jump, its cases reconverging at the
    /// selector's immediate post-dominator. Cases sharing a target are grouped;
    /// each case body is emitted inline and ended with a `break` so they do not
    /// fall through. Returns the follow block to continue from.
    /// The case values, when the range check that guards the dispatch says what
    /// they are.
    ///
    /// A switch is reached by falling through `cmp sel, N` / `ja default`, so
    /// the predecessor's condition carries the upper bound and the values are
    /// `0..=N`. Two things must agree before it is believed: the compared
    /// expression must be the selector, and `N + 1` must be exactly the number
    /// of entries read out of the table. Either one alone can line up by
    /// accident; together they are the same fact told twice.
    fn switch_values(&self, node: usize, sel: &Expr, cases: usize) -> Option<Vec<u64>> {
        for (i, succ) in self.cfg.succ.iter().enumerate() {
            if !succ.contains(&node) {
                continue;
            }
            let Term::Cond { cond, .. } = &self.cfg.term[i] else {
                continue;
            };
            // `ja default` guards the dispatch, so the taken edge leaves it and
            // the condition reads as `sel > N`.
            let Expr::Bin(">", left, right) = cond else {
                continue;
            };
            let Expr::Const(hi) = right.as_ref() else {
                continue;
            };
            if left.as_ref() != sel {
                continue;
            }
            if (*hi as usize).checked_add(1) != Some(cases) {
                continue;
            }
            return Some((0..=*hi).collect());
        }
        None
    }

    fn emit_switch(
        &mut self,
        node: usize,
        sel: Expr,
        cases: Vec<usize>,
        stop: Option<usize>,
        loopc: Option<(usize, usize)>,
        indent: usize,
    ) -> Option<usize> {
        let n_nodes = self.cfg.body.len();
        let ipd = self.ipdom.get(node).copied().unwrap_or(usize::MAX);
        let follow = (ipd < n_nodes).then_some(ipd);
        // Inside a case, `break` leaves the switch (the follow); `continue` still
        // refers to the enclosing loop, if any.
        let cont = loopc.map(|c| c.0).unwrap_or(usize::MAX);
        let case_loopc = follow.map(|f| (cont, f)).or(loopc);

        // Group the case indices that share a target, in first-appearance order.
        let mut groups: Vec<(usize, Vec<usize>)> = Vec::new();
        for (i, &t) in cases.iter().enumerate() {
            match groups.iter_mut().find(|(tt, _)| *tt == t) {
                Some((_, idxs)) => idxs.push(i),
                None => groups.push((t, vec![i])),
            }
        }

        // The only place the real case values exist is the range check that
        // guards the dispatch. Without it the position in the table is all that
        // is known, and a position is not a value: printing `case 0x2:` for the
        // third entry states something about the program that was never checked.
        let values = self.switch_values(node, &sel, cases.len());
        let total = cases.len();

        self.push(indent, format!("switch ({}) {{", render_expr(&sel, self.r)));
        for (t, idxs) in groups {
            for i in idxs {
                match &values {
                    Some(v) => self.push(indent + 1, format!("case 0x{:x}:", v[i])),
                    None => self.push(indent + 1, format!("/* case {} of {total} */", i + 1)),
                }
            }
            if Some(t) == follow {
                // The case goes straight to the reconvergence point.
                self.push(indent + 2, "break;".into());
            } else {
                self.emit(t, stop, case_loopc, indent + 2);
                // Keep the cases from falling through into one another.
                if !self.last_is_transfer() {
                    self.push(indent + 2, "break;".into());
                }
            }
        }
        self.push(indent, "}".into());
        follow
    }

    /// Whether the last emitted line already transfers control, so no `break` is
    /// needed after it.
    fn last_is_transfer(&self) -> bool {
        self.lines.last().is_some_and(|l| {
            let t = l.text.trim_start();
            t.starts_with("break")
                || t.starts_with("continue")
                || t.starts_with("return")
                || t.starts_with("goto")
        })
    }

    /// Emit a `while` loop for header `h` given its recovered shape; return the
    /// loop's follow block.
    fn emit_loop(&mut self, h: usize, shape: (Expr, usize, usize), indent: usize) -> usize {
        let (cond, body_entry, follow) = shape;
        self.node_line[h] = self.lines.len();
        self.node_indent[h] = indent;
        self.emitted[h] = true;

        if self.cfg.body[h].is_empty() {
            // A clean top-tested loop: the header is only the test, so it can be
            // re-evaluated implicitly by `while (cond)`.
            self.push(indent, format!("while ({}) {{", render_expr(&cond, self.r)));
            self.emit(body_entry, None, Some((h, follow)), indent + 1);
        } else {
            // The header does work on each iteration (a counter decrement, a
            // read in the condition), so it cannot be hoisted out. Keep it inside
            // an infinite loop and leave on the exit edge, which also renders a
            // bottom-tested (`do`/`while`) loop faithfully.
            self.push(indent, "while (1) {".into());
            for s in &self.cfg.body[h] {
                self.push(indent + 1, render_stmt(s, self.base, self.r));
            }
            self.push(
                indent + 1,
                format!("if ({}) break;", render_expr(&not(&cond, self.r), self.r)),
            );
            self.emit(body_entry, None, Some((h, follow)), indent + 1);
        }

        // A `continue;` as the loop's very last statement is redundant with
        // falling off the end, so drop it.
        if self
            .lines
            .last()
            .is_some_and(|l| !l.label && l.text.trim() == "continue;")
        {
            self.lines.pop();
        }
        self.push(indent, "}".into());
        follow
    }
}

/// Logical negation of a branch condition, for rendering the inverted arm.
fn not(cond: &Expr, r: Rx) -> Expr {
    if let Expr::Bin(op, l, rr) = cond {
        let inv = match *op {
            "==" => "!=",
            "!=" => "==",
            "<" => ">=",
            ">=" => "<",
            ">" => "<=",
            "<=" => ">",
            _ => return Expr::Opaque(format!("!({})", render_expr(cond, r))),
        };
        return Expr::Bin(inv, l.clone(), rr.clone());
    }
    Expr::Opaque(format!("!({})", render_expr(cond, r)))
}

/// `dst = dst OP rhs` reads better as a compound assignment (`dst OP= rhs`), and
/// a `+`/`-` of one as `dst++` / `dst--`. Any other assignment renders plainly.
fn render_assign(dst: &Expr, src: &Expr, r: Rx) -> String {
    const COMPOUND: &[&str] = &["+", "-", "*", "&", "|", "^", "<<", ">>"];
    if let Expr::Bin(op, l, rhs) = src {
        if l.as_ref() == dst && COMPOUND.contains(op) {
            let d = render_expr(dst, r);
            if matches!(*op, "+" | "-") && matches!(rhs.as_ref(), Expr::Const(1)) {
                return format!("{d}{op}{op};"); // x++ / x--
            }
            return format!("{d} {op}= {};", render_expr(rhs, r));
        }
    }
    format!("{} = {};", render_expr(dst, r), render_expr(src, r))
}

fn render_stmt(s: &Stmt, base: u64, r: Rx) -> String {
    match s {
        Stmt::Set(dst, src) => render_assign(dst, src, r),
        Stmt::CallVoid(e) => format!("{};", render_expr(e, r)),
        Stmt::Ret(Some(e)) => format!("return {};", render_expr(e, r)),
        Stmt::Ret(None) => "return;".to_string(),
        Stmt::Branch(c, t) => format!("if ({}) goto loc_{:x};", render_expr(c, r), t + base),
        Stmt::Goto(t) => format!("goto loc_{:x};", t + base),
        Stmt::Switch(sel) => format!("switch ({}) {{ /* jump table */ }}", render_expr(sel, r)),
        Stmt::Asm { text, .. } => format!("/* {text} */"),
    }
}

/// The name of a frame slot: `var_28` for a local (below the frame pointer),
/// `arg_8` for an argument (above it), `frame` for the base itself.
fn slot_name(off: i64) -> String {
    match off.cmp(&0) {
        std::cmp::Ordering::Less => format!("var_{:x}", off.wrapping_neg()),
        std::cmp::Ordering::Greater => format!("arg_{off:x}"),
        std::cmp::Ordering::Equal => "frame".to_string(),
    }
}

fn display_base(r: Rx, recovered: String) -> String {
    r.db.variable_name(r.function, &recovered)
        .unwrap_or(&recovered)
        .to_string()
}

fn display_register(r: Rx, root: Register, shown: Register) -> String {
    let shown = format!("{shown:?}").to_lowercase();
    if let Some(alias) = r.db.variable_name(r.function, &shown) {
        return alias.to_string();
    }
    let full = format!("{:?}", root.full_register()).to_lowercase();
    r.db.variable_name(r.function, &full)
        .unwrap_or(&shown)
        .to_string()
}

/// The name of a global: its symbol or import name when the engine knows one,
/// otherwise `g_<addr>`.
fn global_name(an: &Analysis, va: u64) -> String {
    an.names
        .get(&va)
        .or_else(|| an.imports.get(&va))
        .cloned()
        .unwrap_or_else(|| format!("g_{va:x}"))
}

/// A global's name, or the string literal it points at, as an address: the
/// address of a `char[]` in C is the string itself, so `&"..."` reduces to
/// `"..."`.
fn global_addr(r: Rx, va: u64) -> String {
    match r.strings.get(&va) {
        Some(s) => quote(&s.text),
        None => format!("&{}", global_name(r.an, va)),
    }
}

fn simple_field_base(e: &Expr) -> bool {
    match e {
        Expr::Reg(root, _) => !is_stack_reg(*root),
        Expr::Mem(_) | Expr::Global(_) | Expr::Call(_, _) => true,
        _ => false,
    }
}

fn field_base_identity(e: &Expr, r: Rx) -> Option<String> {
    let identity = match e {
        Expr::Reg(_, shown) => format!("{shown:?}").to_lowercase(),
        Expr::Mem(a) => match a.as_ref() {
            Expr::Stack(off) => slot_name(*off),
            _ => return None,
        },
        Expr::Global(va) => global_name(r.an, *va),
        Expr::Call(name, _) => crate::analysis::thunks::bare_name(name).to_string(),
        _ => return None,
    };
    crate::db::valid_base(&identity).then_some(identity)
}

fn render_field(base: &Expr, op: &str, offset: u64, r: Rx) -> String {
    let shown_base = render_expr(base, r);
    let signed = if op == "-" {
        i64::try_from(offset).ok().and_then(i64::checked_neg)
    } else {
        i64::try_from(offset).ok()
    };
    let named = field_base_identity(base, r).and_then(|identity| {
        signed.and_then(|offset| r.db.field_name(r.function, &identity, offset))
    });
    match (named, op) {
        (Some(name), _) => format!("{shown_base}->{name}"),
        (None, "-") => format!("{shown_base}->field_m{offset:x}"),
        (None, _) => format!("{shown_base}->field_{offset:x}"),
    }
}

fn render_expr(e: &Expr, r: Rx) -> String {
    match e {
        // An immediate that is exactly the address of a string literal is a
        // pointer to it (32-bit `push offset aString`), so read it as the text.
        Expr::Const(v) => match r.strings.get(v) {
            Some(s) => quote(&s.text),
            None => render_const(*v),
        },
        Expr::Reg(root, shown) => display_register(r, *root, *shown),
        Expr::Stack(off) => display_base(r, slot_name(*off)),
        Expr::Global(va) => global_name(r.an, *va),
        // A frame slot or global reads as its name, not `*(name)`; its address
        // reads as `&name`, or the quoted text when it points at a string.
        Expr::Mem(a) => match a.as_ref() {
            Expr::Stack(off) => display_base(r, slot_name(*off)),
            Expr::Global(va) => global_name(r.an, *va),
            Expr::Bin(op @ ("+" | "-"), base, offset)
                if simple_field_base(base)
                    && matches!(offset.as_ref(), Expr::Const(value) if *value != 0) =>
            {
                let Expr::Const(offset) = offset.as_ref() else {
                    unreachable!("guarded above")
                };
                render_field(base, op, *offset, r)
            }
            _ => format!("*({})", render_expr(a, r)),
        },
        Expr::Addr(a) => match a.as_ref() {
            Expr::Stack(off) => format!("&{}", display_base(r, slot_name(*off))),
            Expr::Global(va) => global_addr(r, *va),
            _ => format!("&({})", render_expr(a, r)),
        },
        Expr::Bin(op, l, r2) => {
            // Parenthesised by C's own binding, not by how the tree happens to
            // be shaped. Nesting was printed flat, so `(a & b) == c` came out as
            // `a & b == c` — which C reads as `a & (b == c)`, a different
            // expression with a different value. Pseudocode that cannot be
            // trusted to mean what it says is worse than none.
            let outer = precedence(op);
            let side = |e: &Expr, right: bool| {
                let text = render_expr(e, r);
                let inner = match e {
                    Expr::Bin(op, _, _) => precedence(op),
                    // A conditional binds looser than every binary operator.
                    Expr::Ternary(..) => 0,
                    _ => u8::MAX,
                };
                // Equal precedence still needs bracketing on the right: these
                // operators associate leftwards, so `a - (b - c)` is not
                // `a - b - c`.
                if inner < outer || (right && inner == outer) {
                    format!("({text})")
                } else {
                    text
                }
            };
            format!("{} {op} {}", side(l, false), side(r2, true))
        }
        // A join the structurer could not turn into a conditional. Name the
        // register the value lives in rather than the analysis term for it: the
        // reader can follow a register back through the branches above and see
        // where each value came from, which `phi(0x0, 0x1)` gives no way to do.
        Expr::Phi(register, _) => render_expr(&Expr::Reg(*register, *register), r),
        Expr::Ternary(c, a, b) => format!(
            "{} ? {} : {}",
            render_expr(c, r),
            render_expr(a, r),
            render_expr(b, r)
        ),
        Expr::Call(name, args) => {
            let a: Vec<String> = args.iter().map(|x| render_expr(x, r)).collect();
            format!("{name}({})", a.join(", "))
        }
        // Unary binds tighter than every binary operator, so anything compound
        // beneath it must be bracketed: `-(a + b)` is not `-a + b`.
        Expr::Un(op, a) => {
            let text = render_expr(a, r);
            match a.as_ref() {
                Expr::Bin(..) | Expr::Ternary(..) => format!("{op}({text})"),
                _ => format!("{op}{text}"),
            }
        }
        Expr::Opaque(s) => s.clone(),
    }
}

/// How tightly a C operator binds. Higher wins; anything unrecognised is
/// treated as the loosest, so an operator added later is bracketed rather than
/// silently mis-grouped.
///
/// This is C's table, not the lifter's: the output is read as C, so it is C's
/// rules that decide whether the text means what the tree does. The trap is
/// `&`, `^` and `|`, which bind *looser* than the comparisons — a mistake old
/// enough to have its own compiler warning.
/// A constant, written the way it most likely was. A small negative that has
/// been sign-extended to 64 bits prints as itself: `cmp rax, -1` says what it
/// means, where `0xffffffffffffffff` leaves the reader to do the arithmetic and
/// invites them to read a sentinel as a mask.
///
/// Only where it is unambiguous — the whole top half set, so this is a widened
/// negative and not a 32-bit value that happens to end in `f`s — and only for
/// small magnitudes, so that a real mask such as `0xffffffff00000000` still
/// prints as the mask it is.
fn render_const(v: u64) -> String {
    let signed = v as i64;
    if v > u64::from(u32::MAX) && (-0x10000..0).contains(&signed) {
        format!("-0x{:x}", signed.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

fn precedence(op: &str) -> u8 {
    match op {
        "*" | "/" | "%" => 10,
        "+" | "-" => 9,
        "<<" | ">>" => 8,
        "<" | ">" | "<=" | ">=" => 7,
        "==" | "!=" => 6,
        "&" => 5,
        "^" => 4,
        "|" => 3,
        _ => 1,
    }
}

// ── small helpers ─────────────────────────────────────────────────────────

/// An unmodelled instruction, together with the registers it writes and reads.
///
/// Read off the decoder rather than guessed: `used_registers` reports every
/// operand access including the implicit ones, which is exactly what is needed
/// here — the whole problem with an instruction we cannot describe is that its
/// effects are mostly implicit (`div` writing `rdx:rax`, `cdq` writing `edx`).
/// Roots only, since propagation and liveness are both keyed by full register.
fn asm_stmt(d: &Instruction) -> Stmt {
    let mut info = InstructionInfoFactory::new();
    let mut defs = Vec::new();
    let mut uses = Vec::new();
    for u in info.info(d).used_registers() {
        let r = u.register().full_register();
        // A conditional access counts as an access: whether it happened is
        // exactly what we cannot tell, so the safe reading is that it did.
        let (writes, reads) = match u.access() {
            OpAccess::Write | OpAccess::CondWrite => (true, false),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => (true, true),
            OpAccess::Read | OpAccess::CondRead => (false, true),
            _ => (false, false),
        };
        if writes && !defs.contains(&r) {
            defs.push(r);
        }
        if reads && !uses.contains(&r) {
            uses.push(r);
        }
    }
    Stmt::Asm {
        text: raw(d),
        defs,
        uses,
    }
}

fn raw(d: &Instruction) -> String {
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_uppercase_hex(false);
    fmt.options_mut().set_hex_prefix("0x");
    fmt.options_mut().set_hex_suffix("");
    let mut s = String::new();
    fmt.format(d, &mut s);
    s
}

/// How to write a call whose target is not a fixed address.
///
/// `call rax` and `call [rbx+0x18]` have a real callee; what is missing is its
/// name, not the call. Naming the operand keeps that visible. The placeholder
/// this replaces read as a call to a function actually named `sub`, which is
/// also the prefix every function Knife recovers without a symbol carries.
fn indirect_callee(d: &Instruction) -> String {
    if d.op_count() == 0 {
        return "sub".to_string();
    }
    match d.op_kind(0) {
        OpKind::Register => format!("(*{})", operand_text(d, 0)),
        OpKind::Memory => {
            // `qword ptr [rbx+0x18]` is assembly's way of writing a
            // dereference. Drop the size, which pseudocode has no use for, and
            // the brackets, which it spells differently.
            let mut fmt = IntelFormatter::new();
            fmt.options_mut().set_hex_prefix("0x");
            fmt.options_mut().set_hex_suffix("");
            fmt.options_mut()
                .set_memory_size_options(MemorySizeOptions::Never);
            let mut text = String::new();
            let _ = fmt.format_operand(d, &mut text, 0);
            let inner = text
                .strip_prefix('[')
                .and_then(|t| t.strip_suffix(']'))
                .unwrap_or(&text);
            format!("(*({inner}))")
        }
        _ => "sub".to_string(),
    }
}

fn operand_text(d: &Instruction, i: u32) -> String {
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_hex_prefix("0x");
    fmt.options_mut().set_hex_suffix("");
    let mut s = String::new();
    let _ = fmt.format_operand(d, &mut s, i);
    s
}

fn branch_target(d: &Instruction) -> Option<u64> {
    matches!(
        d.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| d.near_branch_target())
}

fn is_jcc(m: Mnemonic) -> bool {
    format!("{m:?}").starts_with('J') && m != Mnemonic::Jmp
}

fn is_setcc(m: Mnemonic) -> bool {
    format!("{m:?}").starts_with("Set")
}

fn is_cmovcc(m: Mnemonic) -> bool {
    format!("{m:?}").starts_with("Cmov")
}

/// The `jcc` a `setcc` or `cmovcc` shares its condition with, so the one
/// `condition` mapping serves all three.
fn cc_to_jcc(m: Mnemonic) -> Option<Mnemonic> {
    use Mnemonic::*;
    Some(match m {
        Sete | Cmove => Je,
        Setne | Cmovne => Jne,
        Setl | Cmovl => Jl,
        Setle | Cmovle => Jle,
        Setg | Cmovg => Jg,
        Setge | Cmovge => Jge,
        Setb | Cmovb => Jb,
        Setbe | Cmovbe => Jbe,
        Seta | Cmova => Ja,
        Setae | Cmovae => Jae,
        Sets | Cmovs => Js,
        Setns | Cmovns => Jns,
        _ => return None,
    })
}

/// The flag-setting arithmetic and logic ops whose result a following `jcc`
/// tests against zero. `cmp` and `test` are handled separately.
fn sets_zero_flags(m: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        m,
        Add | Sub | And | Or | Xor | Inc | Dec | Shl | Shr | Sal | Sar | Neg
    )
}

/// Instructions that leave the flags untouched, so a recovered comparison stays
/// valid across them (a `mov`/`lea` between a `cmp` and the `jcc` that reads it,
/// or the fall-through from one conditional jump to the next).
fn preserves_flags(m: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        m,
        Mov | Movzx | Movsx | Movsxd | Lea | Push | Pop | Nop | Endbr32 | Endbr64
        // the sign fills and the widenings touch no flags, so a compare
        // survives across one
        | Cdq | Cqo | Cwd | Cbw | Cwde | Cdqe
        // `not` is the one bitwise instruction that leaves the flags alone
        | Not
    ) || is_sse_move(m)
        || matches!(
            m,
            Addsd | Addss | Subsd | Subss | Mulsd | Mulss | Divsd | Divss | Xorps | Xorpd | Pxor
            // their AVX twins, plus the state hint and the padding trap
            | Vaddsd | Vaddss | Vsubsd | Vsubss | Vmulsd | Vmulss | Vdivsd | Vdivss
            | Vxorps | Vxorpd | Vpxor | Vzeroupper | Int3
        )
        || fma_of(m).is_some()
        || cast_of(m).is_some() || format!("{m:?}").starts_with('J')
        // setcc/cmov read the flags but do not change them, so a compare survives
        // for a following conditional that shares it.
        || is_setcc(m)
        || is_cmovcc(m)
}

fn condition(m: Mnemonic, cmp: &Option<(Expr, Expr, FlagSrc)>) -> Expr {
    let bin = |op: &'static str, l: Expr, r: Expr| Expr::Bin(op, Box::new(l), Box::new(r));
    let Some((l, r, src)) = cmp.clone() else {
        // No comparison was recovered (for instance the flags were set in an
        // earlier block); show the raw condition rather than invent operands.
        return Expr::Opaque(format!("{m:?}").to_lowercase());
    };
    match src {
        FlagSrc::Compare => {
            let op = match m {
                Mnemonic::Je => "==",
                Mnemonic::Jne => "!=",
                Mnemonic::Jg | Mnemonic::Ja => ">",
                Mnemonic::Jge | Mnemonic::Jae => ">=",
                Mnemonic::Jl | Mnemonic::Jb => "<",
                Mnemonic::Jle | Mnemonic::Jbe => "<=",
                _ => return Expr::Opaque(format!("{m:?}").to_lowercase()),
            };
            bin(op, l, r)
        }
        // A result compared against zero. The unsigned conditions (`ja`/`jb`
        // and friends) are carry-based and not expressible as "result vs 0", so
        // they fall back to the raw condition rather than a wrong comparison.
        // The zero-source variants that additionally pin the carry flag read
        // the zero-testable conditions identically; only `sbb` tells them apart.
        FlagSrc::Zero | FlagSrc::ZeroClearsCf | FlagSrc::NegResult => {
            let op = match m {
                Mnemonic::Je => "==",
                Mnemonic::Jne => "!=",
                Mnemonic::Jg => ">",
                Mnemonic::Jge | Mnemonic::Jns => ">=",
                Mnemonic::Jl | Mnemonic::Js => "<",
                Mnemonic::Jle => "<=",
                _ => return Expr::Opaque(format!("{m:?}").to_lowercase()),
            };
            bin(op, l, Expr::Const(0))
        }
        // The carry flag holds the one tested bit: `jc` asks whether it is
        // set, `jnc` whether it is clear. Nothing else about these flags is
        // defined, so any other condition stays raw rather than a guess.
        FlagSrc::Bit => {
            let op = match m {
                Mnemonic::Jb => "==",
                Mnemonic::Jae => "!=",
                _ => return Expr::Opaque(format!("{m:?}").to_lowercase()),
            };
            bin(op, l, Expr::Const(1))
        }
    }
}

fn strip_module(name: &str) -> String {
    let n = name.rsplit_once('!').map(|(_, f)| f).unwrap_or(name);
    n.strip_suffix("@plt").unwrap_or(n).to_string()
}

fn call_target(d: &Instruction, an: &Analysis, bin: &Binary) -> Option<u64> {
    let _ = bin;
    if let Some(t) = branch_target(d) {
        return Some(t);
    }
    if d.is_ip_rel_memory_operand() {
        let slot = d.ip_rel_memory_address();
        if an.imports.contains_key(&slot) {
            return Some(slot);
        }
    }
    None
}

fn arg_registers(win64: bool) -> &'static [Register] {
    if win64 {
        &[Register::RCX, Register::RDX, Register::R8, Register::R9]
    } else {
        &[
            Register::RDI,
            Register::RSI,
            Register::RDX,
            Register::RCX,
            Register::R8,
            Register::R9,
        ]
    }
}

fn arity(name: &str) -> Option<usize> {
    let bare = crate::analysis::thunks::bare_name(name);
    let legacy = match bare {
        "malloc" | "free" | "atoi" | "puts" | "strlen" | "system" => 1,
        "strcpy" | "strcat" | "lstrcpyA" | "lstrcpyW" | "lstrcatA" | "lstrcatW" => 2,
        "memcpy" | "memmove" | "memset" | "strncpy" | "strncat" | "snprintf" => 3,
        _ => return prototype(name).map(|(_, args)| args.len()),
    };
    Some(legacy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::engine;
    use crate::db::Db;
    use crate::model::{Arch, Section, SymKind, Symbol};

    fn lines_x86(sink: &str, mut code: Vec<u8>) -> Vec<Line> {
        let (va, slot) = (0x1000u64, 0x4000u64);
        code.push(0xff);
        code.push(0x15);
        code.extend_from_slice(&(slot as u32).to_le_bytes());
        code.push(0xc3);
        let mut bin = Binary::stub(Format::Pe, Arch::X86);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        bin.symbols = vec![Symbol {
            addr: slot,
            name: sink.into(),
            kind: SymKind::Import,
            size: None,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let f = an.find_function(va).unwrap();
        decompile(&an, &bin, f, &BTreeMap::new(), &Db::default())
    }

    #[test]
    fn an_internal_x64_call_recovers_arguments_from_the_callee() {
        let va = 0x1000u64;
        // caller: mov ecx,7; mov edx,9; call 0x1020; ret
        let mut code = vec![
            0xb9, 0x07, 0x00, 0x00, 0x00, 0xba, 0x09, 0x00, 0x00, 0x00, 0xe8, 0x11, 0x00, 0x00,
            0x00, 0xc3,
        ];
        code.resize(0x20, 0x90);
        // callee: lea eax,[rcx+rdx]; ret. Both incoming ABI registers are read
        // before definition, proving a two-argument internal function.
        code.extend_from_slice(&[0x8d, 0x04, 0x11, 0xc3]);
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let caller = an.find_function(va).expect("caller");
        let lines = decompile(&an, &bin, caller, &BTreeMap::new(), &Db::default());
        let joined = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("sub_1020(0x7, 0x9)"),
            "callee-derived arity should preserve both arguments:\n{joined}"
        );
    }

    #[test]
    fn an_internal_wrapper_propagates_a_known_return_type() {
        let va = 0x1000u64;
        // caller: call wrapper; ret
        let mut code = vec![0xe8, 0x1b, 0x00, 0x00, 0x00, 0xc3];
        code.resize(0x20, 0x90);
        // wrapper: mov ecx,0x20; call [malloc_slot]; ret
        code.extend_from_slice(&[
            0xb9, 0x20, 0x00, 0x00, 0x00, 0xff, 0x15, 0xd5, 0x0f, 0x00, 0x00, 0xc3,
        ]);
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        bin.symbols = vec![Symbol {
            addr: 0x2000,
            name: "malloc".into(),
            kind: SymKind::Import,
            size: None,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let caller = an.find_function(va).expect("caller");
        let lines = decompile(&an, &bin, caller, &BTreeMap::new(), &Db::default());
        assert_eq!(
            internal_return_type(&an, &bin, "sub_1020"),
            Some(CType::VoidPtr),
            "the wrapper itself must have a stable summary"
        );
        let signatures = an
            .functions
            .iter()
            .map(|function| {
                let rendered = decompile(&an, &bin, function, &BTreeMap::new(), &Db::default());
                format!(
                    "{:x} {} => {}\n{}",
                    function.addr,
                    function.name,
                    rendered.first().map_or("", |line| line.text.as_str()),
                    rendered
                        .iter()
                        .map(|line| line.text.as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            lines
                .first()
                .is_some_and(|line| line.text.starts_with("void * entry(")),
            "wrapper return type should reach the caller:\n{signatures}"
        );
    }

    #[test]
    fn an_overwritten_wrapper_return_does_not_propagate_a_stale_type() {
        let va = 0x1000u64;
        let mut code = vec![0xe8, 0x1b, 0x00, 0x00, 0x00, 0xc3];
        code.resize(0x20, 0x90);
        // The call returns void *, but xor eax,eax replaces that value before
        // ret, so the wrapper's source-level return type is not proven.
        code.extend_from_slice(&[
            0xb9, 0x20, 0x00, 0x00, 0x00, 0xff, 0x15, 0xd5, 0x0f, 0x00, 0x00, 0x31, 0xc0, 0xc3,
        ]);
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        bin.symbols = vec![Symbol {
            addr: 0x2000,
            name: "malloc".into(),
            kind: SymKind::Import,
            size: None,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        assert_eq!(internal_return_type(&an, &bin, "sub_1020"), None);
        let caller = an.find_function(va).expect("caller");
        let lines = decompile(&an, &bin, caller, &BTreeMap::new(), &Db::default());
        assert!(
            lines
                .first()
                .is_some_and(|line| line.text.starts_with("uintptr_t entry(")),
            "an overwritten call result must remain conservative: {lines:?}"
        );
    }

    #[test]
    fn an_internal_callee_propagates_a_parameter_type_to_its_caller() {
        let va = 0x1000u64;
        // caller: return sub_1020(rcx)
        let mut code = vec![0xe8, 0x1b, 0x00, 0x00, 0x00, 0xc3];
        code.resize(0x20, 0x90);
        // wrapper: preserve rcx through rax, then pass it to strlen. The copy
        // makes the incoming parameter use explicit in machine semantics while
        // exercising provenance across a register hop.
        code.extend_from_slice(&[
            0x48, 0x89, 0xc8, // mov rax,rcx
            0x48, 0x89, 0xc1, // mov rcx,rax
            0xff, 0x15, 0xd4, 0x0f, 0x00, 0x00, // call [strlen_slot]
            0xc3,
        ]);
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        bin.symbols = vec![Symbol {
            addr: 0x2000,
            name: "strlen".into(),
            kind: SymKind::Import,
            size: None,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        assert_eq!(
            internal_parameter_types(&an, &bin, "sub_1020"),
            Some(vec![CType::ConstCharPtr])
        );
        let caller = an.find_function(va).expect("caller");
        let lines = decompile(&an, &bin, caller, &BTreeMap::new(), &Db::default());
        assert!(
            lines
                .first()
                .is_some_and(|line| { line.text.starts_with("size_t entry(const char * rcx)") }),
            "callee parameter evidence should type the caller: {lines:?}"
        );
    }

    #[test]
    fn an_overwritten_callee_argument_does_not_propagate_a_stale_type() {
        let va = 0x1000u64;
        let mut code = vec![0xe8, 0x1b, 0x00, 0x00, 0x00, 0xc3];
        code.resize(0x20, 0x90);
        // rcx is observed, proving the wrapper has one input, but is replaced
        // before strlen. The API's pointer constraint belongs to zero, not to
        // the original caller argument.
        code.extend_from_slice(&[
            0x48, 0x89, 0xc8, // mov rax,rcx
            0x31, 0xc9, // xor ecx,ecx
            0xff, 0x15, 0xd5, 0x0f, 0x00, 0x00, // call [strlen_slot]
            0xc3,
        ]);
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        bin.symbols = vec![Symbol {
            addr: 0x2000,
            name: "strlen".into(),
            kind: SymKind::Import,
            size: None,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        assert_eq!(
            internal_parameter_types(&an, &bin, "sub_1020"),
            Some(vec![CType::Unknown])
        );
        let caller = an.find_function(va).expect("caller");
        let lines = decompile(&an, &bin, caller, &BTreeMap::new(), &Db::default());
        assert!(
            lines
                .first()
                .is_some_and(|line| line.text.starts_with("size_t entry(uintptr_t rcx)")),
            "overwritten provenance must remain pointer-sized and unknown: {lines:?}"
        );
    }

    #[test]
    fn an_internal_callee_types_a_callers_stack_buffer() {
        let va = 0x1000u64;
        // caller: allocate a frame, pass &var_8 to the wrapper, restore, ret.
        let mut code = vec![
            0x48, 0x83, 0xec, 0x28, // sub rsp,0x28
            0x48, 0x8d, 0x4c, 0x24, 0x20, // lea rcx,[rsp+0x20]
            0xe8, 0x32, 0x00, 0x00, 0x00, // call 0x1040
            0x48, 0x83, 0xc4, 0x28, // add rsp,0x28
            0xc3,
        ];
        code.resize(0x40, 0x90);
        // wrapper forwards its input to strlen through rax.
        code.extend_from_slice(&[
            0x48, 0x89, 0xc8, 0x48, 0x89, 0xc1, 0xff, 0x15, 0xb4, 0x0f, 0x00, 0x00, 0xc3,
        ]);
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        bin.symbols = vec![Symbol {
            addr: 0x2000,
            name: "strlen".into(),
            kind: SymKind::Import,
            size: None,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let caller = an.find_function(va).expect("caller");
        let lines = decompile(&an, &bin, caller, &BTreeMap::new(), &Db::default());
        assert!(
            lines
                .iter()
                .any(|line| line.text.trim() == "char var_8[]; /* extent unresolved */"),
            "the wrapper's pointee type should reach caller storage: {lines:?}"
        );
    }

    #[test]
    fn dead_intermediate_assignments_are_removed() {
        // mov eax,[ebp+8]; add eax,0x1c; push eax; lea eax,[ebp-0x28]; push eax; call
        // The two eax computations feed the call and are dead afterward, so only
        // the call statement should survive.
        //
        // Nothing establishes ebp as a frame pointer here, so the `lea` stays
        // raw arithmetic: its value is `ebp - 0x28`, and that is what it says.
        // A function with a real prologue gets `&var_28` instead.
        let code = vec![
            0x8b, 0x45, 0x08, 0x83, 0xc0, 0x1c, 0x50, 0x8d, 0x45, 0xd8, 0x50,
        ];
        let lines = lines_x86("lstrcpyA", code);
        let stmts: Vec<&str> = lines
            .iter()
            .filter(|l| !l.label)
            .map(|l| l.text.as_str())
            .collect();
        // The call, rendered with both arguments propagated in, is one line.
        assert!(
            stmts
                .iter()
                .any(|s| s.contains("lstrcpyA(ebp - 0x28, *(ebp + 0x8) + 0x1c)")),
            "call with propagated args, got: {stmts:?}"
        );
        // The intermediate loads that fed the arguments are dead and removed:
        // the `*(ebp + 0x8)` expression appears only inside the call, never as a
        // standalone assignment.
        assert!(
            !stmts
                .iter()
                .any(|s| s.contains("*(ebp + 0x8)") && !s.contains("lstrcpyA")),
            "dead intermediate loads should be gone, got: {stmts:?}"
        );
    }

    #[test]
    fn constant_arithmetic_is_folded() {
        // mov eax, 0x10; add eax, 0x20; push eax; call malloc -> malloc(0x30)
        let code = vec![
            0xb8, 0x10, 0x00, 0x00, 0x00, // mov eax, 0x10
            0x83, 0xc0, 0x20, // add eax, 0x20
            0x50, // push eax
        ];
        let lines = lines_x86("malloc", code);
        assert!(
            lines.iter().any(|l| l.text.contains("malloc(0x30)")),
            "0x10 + 0x20 should fold to 0x30: {:?}",
            lines.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
    }

    fn framed_copy(name: &str) -> Vec<Line> {
        // push ebp; mov ebp,esp; sub esp,20h; source=arg_8; dest=&var_20.
        lines_x86(
            name,
            vec![
                0x55, 0x8b, 0xec, 0x83, 0xec, 0x20, 0x8b, 0x45, 0x08, 0x50, 0x8d, 0x45, 0xe0, 0x50,
            ],
        )
    }

    #[test]
    fn a_narrow_string_api_recovers_a_character_stack_buffer() {
        let joined = framed_copy("lstrcpyA")
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("char var_20[]; /* extent unresolved */"),
            "the destination local should be declared from lstrcpyA's prototype:\n{joined}"
        );
    }

    #[test]
    fn a_wide_string_api_recovers_a_wide_character_stack_buffer() {
        let joined = framed_copy("lstrcpyW")
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("wchar_t var_20[]; /* extent unresolved */"),
            "the destination local should be declared from lstrcpyW's prototype:\n{joined}"
        );
    }

    #[test]
    fn conflicting_pointee_evidence_degrades_a_local_to_raw_bytes() {
        let local = Expr::Addr(Box::new(Expr::Stack(-0x20)));
        let blocks = [IrBlock {
            start: 0x1000,
            stmts: vec![
                Stmt::CallVoid(Expr::Call(
                    "lstrcpyA".into(),
                    vec![local.clone(), Expr::Opaque("src_a".into())],
                )),
                Stmt::CallVoid(Expr::Call(
                    "lstrcpyW".into(),
                    vec![local, Expr::Opaque("src_w".into())],
                )),
            ],
            succ: Vec::new(),
        }];
        assert_eq!(
            local_declarations(&blocks, &BTreeMap::new(), &Db::default(), 0),
            vec!["uint8_t var_20[]; /* extent unresolved */"]
        );
    }

    #[test]
    fn a_direct_stack_slot_recovers_a_scalar_type() {
        let blocks = [IrBlock {
            start: 0x1000,
            stmts: vec![Stmt::Set(
                Expr::Mem(Box::new(Expr::Stack(-8))),
                Expr::Bin(
                    "==",
                    Box::new(Expr::Reg(Register::RAX, Register::EAX)),
                    Box::new(Expr::Const(0)),
                ),
            )],
            succ: Vec::new(),
        }];
        assert_eq!(
            local_declarations(&blocks, &BTreeMap::new(), &Db::default(), 0),
            vec!["bool var_8;"]
        );
    }

    #[test]
    fn an_unmodelled_instruction_stays_verbatim() {
        let lines = lines_x86("puts", vec![0x0f, 0xa2]); // cpuid
        assert!(lines
            .iter()
            .any(|l| l.text.contains("/*") && l.text.contains("cpuid")));
    }

    #[test]
    fn an_aarch64_image_is_refused_rather_than_decompiled_as_x86() {
        // The lifter decodes with iced_x86 whatever the target is, so an ARM64
        // word was being read as x86 and turned into statements about registers
        // the machine does not have. It must say what it cannot do instead.
        let bytes = crate::formats::fixture::elf_aarch64_call();
        let bin = crate::formats::analyze("fixture", &bytes).unwrap();
        assert_eq!(bin.arch, Arch::Aarch64, "fixture should be AArch64");
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let f = an.functions.first().expect("a recovered function");
        let lines = decompile(&an, &bin, f, &BTreeMap::new(), &Db::default());
        let text = lines
            .iter()
            .map(|l| l.text.clone())
            .collect::<Vec<_>>()
            .join(
                "
",
            );
        assert!(
            text.contains("x86/x64 only") && text.contains("AArch64"),
            "should name what it cannot do: {text}"
        );
        // And must not have invented anything about x86 registers.
        for reg in ["rax", "rcx", "rdx", "rsp", "eax"] {
            assert!(
                !text.contains(reg),
                "invented an x86 register ({reg}) for an ARM64 image: {text}"
            );
        }
    }

    #[test]
    fn a_mask_test_keeps_both_operands() {
        // mov rax, [rcx+0x18] ; and rax, rdx ; test rax, rdx ; jne +0 ; ret
        //
        // `test a, b` sets the flags from `a & b`. Reading only the first
        // operand turns a mask test into a null check, which is a different
        // question about different data.
        let code = vec![
            0x48, 0x85, 0xd1, // test rcx, rdx
            0x75, 0x01, // jne +1
            0xc3, // ret
            0xc3, // ret
        ];
        let text: String = lines_x64_raw(code)
            .iter()
            .map(|l| l.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("rcx & rdx"),
            "both operands belong in a mask test: {text}"
        );
    }

    #[test]
    fn a_masked_comparison_is_bracketed_as_c_reads_it() {
        // mov rax, [rcx+0x18] ; and rax, rdx ; cmp rax, [rcx+0x18] ; jne ; ret
        //
        // Taken from a real flags check. The comparison is between `field & rdx`
        // and `field`, and C binds `==` tighter than `&`: printed without
        // brackets the line reads as `field & (rdx == field)`, which is a
        // different expression that happens to still compile.
        let code = vec![
            0x48, 0x8b, 0x41, 0x18, // mov rax, [rcx+0x18]
            0x48, 0x21, 0xd0, // and rax, rdx
            0x48, 0x3b, 0x41, 0x18, // cmp rax, [rcx+0x18]
            0x75, 0x01, // jne +1
            0xc3, // ret
            0xc3, // ret
        ];
        let text: String = lines_x64_raw(code)
            .iter()
            .map(|l| l.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("(") && text.contains("&"),
            "the masked side must be bracketed: {text}"
        );
        assert!(
            !text.contains("& rdx =="),
            "an unbracketed mask reads as a different expression: {text}"
        );
    }

    #[test]
    fn an_unmodelled_write_is_not_propagated_past() {
        // mov rax, 5 ; div rcx ; mov rbx, rax ; ret
        //
        // `div` is not modelled, but it writes rax. Carrying the 5 across it
        // would print a value the machine had already thrown away — the worst
        // kind of wrong, because it reads like a fact.
        let code = vec![
            0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
            0x48, 0xf7, 0xf1, // div rcx
            0x48, 0x89, 0xc3, // mov rbx, rax
            0xc3, // ret
        ];
        let text: String = lines_x64_raw(code)
            .iter()
            .map(|l| l.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("div"),
            "the division should still be shown: {text}"
        );
        assert!(
            !text.contains("rbx = 0x5"),
            "the value from before the division must not survive it: {text}"
        );
    }

    fn joined_x64(code: Vec<u8>) -> String {
        lines_x64_raw(code)
            .iter()
            .map(|l| l.text.clone())
            .collect::<Vec<_>>()
            .join(
                "
",
            )
    }

    #[test]
    fn an_unsigned_divide_with_a_cleared_high_half_is_division() {
        // mov eax, ecx ; xor edx, edx ; mov r9d, 10 ; div r9d ; ret
        //
        // `xor edx, edx` proves the dividend is just eax, so the whole of the
        // division is `ecx / 10` and there is nothing left over to hide.
        let code = vec![
            0x8b, 0xc1, // mov eax, ecx
            0x31, 0xd2, // xor edx, edx
            0x41, 0xb9, 0x0a, 0x00, 0x00, 0x00, // mov r9d, 10
            0x41, 0xf7, 0xf1, // div r9d
            0xc3, // ret
        ];
        let text = joined_x64(code);
        assert!(
            text.contains(" / "),
            "the divide should read as division:
{text}"
        );
        assert!(
            !text.contains("div "),
            "it should not stay verbatim:
{text}"
        );
    }

    #[test]
    fn a_signed_divide_reads_the_sign_fill_that_set_it_up() {
        // mov eax, ecx ; mov r9d, 10 ; cdq ; idiv r9d ; ret
        //
        // `cdq` fills edx with the sign of eax, which is what makes the
        // dividend exactly eax. The fill itself then has no reader and should
        // not survive into the output as a stray shift.
        let code = vec![
            0x8b, 0xc1, // mov eax, ecx
            0x41, 0xb9, 0x0a, 0x00, 0x00, 0x00, // mov r9d, 10
            0x99, // cdq
            0x41, 0xf7, 0xf9, // idiv r9d
            0xc3, // ret
        ];
        let text = joined_x64(code);
        assert!(
            text.contains(" / "),
            "the signed divide should read as division:
{text}"
        );
        assert!(
            !text.contains("idiv"),
            "it should not stay verbatim:
{text}"
        );
        assert!(
            !text.contains(">> 31"),
            "the sign fill has no reader and should be dropped:
{text}"
        );
    }

    #[test]
    fn a_genuine_double_width_dividend_is_left_unmodelled() {
        // mov edx, 5 ; mov eax, 100 ; mov r9d, 7 ; div r9d ; ret
        //
        // edx holds a value of its own, so this divides a 64-bit quantity that
        // no C expression over eax can state. Saying `eax / 7` here would be a
        // confident sentence about half the dividend, which is worse than
        // saying nothing.
        let code = vec![
            0xba, 0x05, 0x00, 0x00, 0x00, // mov edx, 5
            0xb8, 0x64, 0x00, 0x00, 0x00, // mov eax, 100
            0x41, 0xb9, 0x07, 0x00, 0x00, 0x00, // mov r9d, 7
            0x41, 0xf7, 0xf1, // div r9d
            0xc3, // ret
        ];
        let text = joined_x64(code);
        assert!(
            text.contains("div"),
            "it should stay verbatim:
{text}"
        );
        assert!(
            !text.contains(" / "),
            "half a dividend must not be presented as the whole one:
{text}"
        );
    }

    #[test]
    fn a_remainder_that_is_read_survives_as_a_modulo() {
        // mov eax, ecx ; xor edx, edx ; mov r9d, 10 ; div r9d ; mov eax, edx ; ret
        //
        // The remainder is a real result of the instruction. It is dropped when
        // nothing reads it; here the return value is exactly it.
        let code = vec![
            0x8b, 0xc1, // mov eax, ecx
            0x31, 0xd2, // xor edx, edx
            0x41, 0xb9, 0x0a, 0x00, 0x00, 0x00, // mov r9d, 10
            0x41, 0xf7, 0xf1, // div r9d
            0x8b, 0xc2, // mov eax, edx
            0xc3, // ret
        ];
        let text = joined_x64(code);
        assert!(
            text.contains(" % "),
            "the remainder should read as a modulo:
{text}"
        );
    }

    #[test]
    fn the_three_operand_imul_multiplies_its_sources() {
        // mov eax, 9 ; imul eax, ecx, 5 ; mov ebx, eax ; ret
        //
        // `imul eax, ecx, 5` computes `ecx * 5` into eax. Read through the
        // two-operand shape, it printed `eax = eax * ecx` — a different
        // product, silently.
        let code = vec![
            0xb8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9
            0x6b, 0xc1, 0x05, // imul eax, ecx, 5
            0x8b, 0xd8, // mov ebx, eax
            0xc3, // ret
        ];
        let text = joined_x64(code);
        assert!(
            text.contains("ecx * 0x5"),
            "the sources are operand 1 and the immediate:
{text}"
        );
        assert!(
            !text.contains("eax *"),
            "the old destination is not a factor of the three-operand form:
{text}"
        );
    }

    #[test]
    fn a_one_operand_mul_states_both_halves() {
        // mov rax, rcx ; mul rdx ; mov rdi, rax ; mov rsi, rdx ; ret
        //
        // The widening multiply's two results are both values the program can
        // read; the high half is the product shifted down, the same width-blind
        // `>>` the sign fill prints.
        let text = joined_x64(vec![
            0x48, 0x89, 0xc8, // mov rax, rcx
            0x48, 0xf7, 0xe2, // mul rdx
            0x48, 0x89, 0xc7, // mov rdi, rax
            0x48, 0x89, 0xd6, // mov rsi, rdx
            0xc3, // ret
        ]);
        assert!(
            text.contains(">> 0x40"),
            "the high half is the product shifted down by the width:
{text}"
        );
        assert!(
            text.contains("rcx * rdx"),
            "the product is the multiply of its sources:
{text}"
        );
    }

    #[test]
    fn bt_then_jc_reads_the_tested_bit() {
        // bt eax, 3 ; jc +1 ; ret ; ret
        //
        // `bt` reads one bit into the carry flag, and the branch after it asks
        // about exactly that bit. A raw `jb` on an unrecovered comparison
        // would say less than the machine does.
        let code = vec![
            0x0f, 0xba, 0xe0, 0x03, // bt eax, 3
            0x72, 0x01, // jc +1
            0xc3, // ret
            0xc3, // ret
        ];
        let text = joined_x64(code);
        assert!(
            text.contains(">> 0x3") && text.contains("== 0x1"),
            "the branch should read the bit:
{text}"
        );
        assert!(
            !text.contains("/*"),
            "bt must not stay verbatim:
{text}"
        );
    }

    #[test]
    fn bts_sets_the_bit_it_reported() {
        // mov eax, [rcx] ; bts eax, 7 ; mov edx, eax ; ret
        let text = joined_x64(vec![
            0x8b, 0x01, // mov eax, [rcx]
            0x0f, 0xba, 0xe8, 0x07, // bts eax, 7
            0x8b, 0xd0, // mov edx, eax
            0xc3, // ret
        ]);
        assert!(
            text.contains("0x80") && text.contains("|"),
            "bts sets the bit:
{text}"
        );
    }

    #[test]
    fn btr_clears_the_bit_it_reported() {
        // btr ebx, 0x1f ; mov eax, ebx ; ret
        let text = joined_x64(vec![
            0x0f, 0xba, 0xf3, 0x1f, // btr ebx, 0x1f
            0x8b, 0xc3, // mov eax, ebx
            0xc3, // ret
        ]);
        assert!(
            text.contains("~0x80000000") && text.contains("&"),
            "btr clears the bit:
{text}"
        );
    }

    #[test]
    fn sbb_after_cmp_is_the_borrow() {
        // cmp edx, ecx ; sbb ebx, ebx ; mov eax, ebx ; ret
        //
        // MSVC's branchless `-(a < b)`: the carry of the comparison decides
        // between all-ones and zero.
        let code = vec![
            0x3b, 0xd1, // cmp edx, ecx
            0x19, 0xdb, // sbb ebx, ebx
            0x8b, 0xc3, // mov eax, ebx
            0xc3, // ret
        ];
        let text = joined_x64(code);
        assert!(
            text.contains("edx < ecx") && text.contains("? 0xffffffff : 0x0"),
            "the borrow should read as the comparison:
{text}"
        );
    }

    #[test]
    fn sbb_after_test_is_zero() {
        // test eax, eax ; sbb ecx, ecx ; mov eax, ecx ; ret
        //
        // `test` clears the carry flag, defined, so the subtract-with-borrow
        // of itself leaves exactly zero.
        let text = joined_x64(vec![
            0x85, 0xc0, // test eax, eax
            0x19, 0xc9, // sbb ecx, ecx
            0x8b, 0xc1, // mov eax, ecx
            0xc3, // ret
        ]);
        assert!(
            text.contains("return 0x0"),
            "a cleared carry borrows nothing:
{text}"
        );
    }

    #[test]
    fn sbb_after_neg_borrows_on_non_zero() {
        // sub eax, ebx ; neg eax ; sbb cl, cl ; movzx eax, cl ; ret
        //
        // The real pattern behind most of ucrtbase's remaining `sbb`: `neg`
        // sets the carry to the operand's non-zero-ness, so the borrow reads
        // as `result != 0`.
        let text = joined_x64(vec![
            0x2b, 0xc3, // sub eax, ebx
            0xf7, 0xd8, // neg eax
            0x18, 0xc9, // sbb cl, cl
            0x0f, 0xb6, 0xc1, // movzx eax, cl
            0xc3, // ret
        ]);
        assert!(
            text.contains("!= 0x0") && text.contains("? 0xff : 0x0"),
            "a neg's carry is the value being non-zero:
{text}"
        );
    }

    #[test]
    fn avx_moves_are_copies() {
        // vmovaps xmm0, xmm1 ; vmovups [rcx], xmm0 ; ret
        let text = joined_x64(vec![
            0xc5, 0xf8, 0x28, 0xc1, // vmovaps xmm0, xmm1
            0xc5, 0xf8, 0x11, 0x01, // vmovups [rcx], xmm0
            0xc3, // ret
        ]);
        assert!(
            text.contains("*(rcx) = xmm1") && !text.contains("/*"),
            "the AVX move is the copy its legacy twin is:
{text}"
        );
    }

    #[test]
    fn avx_scalar_arithmetic_reads_as_arithmetic() {
        // vaddsd xmm0, xmm1, xmm2 ; vmovsd [rcx], xmm0 ; ret
        let text = joined_x64(vec![
            0xc5, 0xf3, 0x58, 0xc2, // vaddsd xmm0, xmm1, xmm2
            0xc5, 0xfb, 0x11, 0x01, // vmovsd [rcx], xmm0
            0xc3, // ret
        ]);
        assert!(
            text.contains("xmm1 + xmm2") && !text.contains("/*"),
            "the VEX form is three-operand:
{text}"
        );
    }

    #[test]
    fn avx_zeroing_xor_is_zero() {
        // vxorps xmm0, xmm0, xmm0 ; vmovups [rcx], xmm0 ; ret
        let text = joined_x64(vec![
            0xc5, 0xf8, 0x57, 0xc0, // vxorps xmm0, xmm0, xmm0
            0xc5, 0xf8, 0x11, 0x01, // vmovups [rcx], xmm0
            0xc3, // ret
        ]);
        assert!(
            text.contains("*(rcx) = 0x0") && !text.contains("/*"),
            "zeroing is how compilers write 0.0:
{text}"
        );
    }

    #[test]
    fn the_fused_multiply_add_reads_as_its_arithmetic() {
        // vfmadd213sd xmm0, xmm3, xmm4 ; vmovsd [rcx], xmm0 ; ret
        //
        // 213 pairs the destination's old value with xmm3 and adds xmm4.
        let text = joined_x64(vec![
            0xc4, 0xe2, 0xe5, 0xa9, 0xc4, // vfmadd213sd xmm0, xmm3, xmm4
            0xc5, 0xfb, 0x11, 0x01, // vmovsd [rcx], xmm0
            0xc3, // ret
        ]);
        assert!(
            text.contains("xmm0 * xmm3 + xmm4") && !text.contains("/*"),
            "one rounding does a multiply and an add:
{text}"
        );
    }

    #[test]
    fn a_vex_scalar_move_takes_the_copied_lane() {
        // vmovsd xmm1, xmm2, xmm3 ; vmovsd [rcx], xmm1 ; ret
        //
        // The third operand is the lane being copied; the middle one only
        // merges the high half that scalar pseudocode does not see.
        let text = joined_x64(vec![
            0xc5, 0xeb, 0x10, 0xcb, // vmovsd xmm1, xmm2, xmm3
            0xc5, 0xfb, 0x11, 0x09, // vmovsd [rcx], xmm1
            0xc3, // ret
        ]);
        assert!(
            text.contains("*(rcx) = xmm3") && !text.contains("/*"),
            "the copied lane is the value:
{text}"
        );
    }

    #[test]
    fn bmi2_shifts_read_as_shifts() {
        // shlx edx, ecx, eax ; mov eax, edx ; ret
        let text = joined_x64(vec![
            0xc4, 0xe2, 0x79, 0xf7, 0xd1, // shlx edx, ecx, eax
            0x8b, 0xc2, // mov eax, edx
            0xc3, // ret
        ]);
        assert!(
            text.contains("ecx << eax") && !text.contains("/*"),
            "the BMI2 shift is the shift its legacy twin is:
{text}"
        );
    }

    #[test]
    fn an_immediate_rotate_expands_to_its_shifts() {
        // rol eax, 0x10 ; ret
        let code = vec![0xc1, 0xc0, 0x10, 0xc3];
        let text = joined_x64(code);
        assert!(
            text.contains("<< 0x10") && text.contains(">> 0x10") && !text.contains("/*"),
            "a rotate by a constant is exactly two shifts:
{text}"
        );
    }

    #[test]
    fn padding_traps_and_state_hints_are_dropped() {
        // mov eax, ecx ; int3 ; vzeroupper ; ret
        //
        // int3 here is alignment padding between functions and vzeroupper is
        // an AVX state hint; neither has an effect the pseudocode could show.
        let code = vec![
            0x8b, 0xc1, // mov eax, ecx
            0xcc, // int3
            0xc5, 0xf8, 0x77, // vzeroupper
            0xc3, // ret
        ];
        let text = joined_x64(code);
        assert!(
            !text.contains("int3") && !text.contains("vzeroupper"),
            "neither does anything the pseudocode could say:
{text}"
        );
    }

    #[test]
    fn negation_and_complement_read_as_operators() {
        // mov eax, ecx ; neg eax ; ret   →  -ecx
        let text = joined_x64(vec![0x8b, 0xc1, 0xf7, 0xd8, 0xc3]);
        assert!(
            text.contains("-ecx"),
            "neg should read as negation:
{text}"
        );
        assert!(
            !text.contains("neg"),
            "it should not stay verbatim:
{text}"
        );

        // mov eax, ecx ; not eax ; ret   →  ~ecx
        let text = joined_x64(vec![0x8b, 0xc1, 0xf7, 0xd0, 0xc3]);
        assert!(
            text.contains("~ecx"),
            "not should read as complement:
{text}"
        );
        assert!(
            !text.contains("not "),
            "it should not stay verbatim:
{text}"
        );
    }

    #[test]
    fn a_unary_over_a_sum_is_bracketed_as_c_reads_it() {
        // mov eax, ecx ; add eax, edx ; neg eax ; ret
        //
        // `-ecx + edx` is C for `(-ecx) + edx`, a different value. Unary binds
        // tighter than every binary operator, so the sum needs its brackets.
        let text = joined_x64(vec![0x8b, 0xc1, 0x03, 0xc2, 0xf7, 0xd8, 0xc3]);
        assert!(
            text.contains("-(ecx + edx)"),
            "a negated sum must be bracketed:
{text}"
        );
    }

    #[test]
    fn scalar_floating_point_reads_as_arithmetic() {
        // movsd xmm0, [rcx] ; mulsd xmm0, [rdx] ; addsd xmm0, xmm1 ; movsd [rdx], xmm0
        //
        // The result is stored, or the whole chain is dead and correctly
        // deleted before it can be looked at.
        let text = joined_x64(vec![
            0xf2, 0x0f, 0x10, 0x01, // movsd xmm0, qword ptr [rcx]
            0xf2, 0x0f, 0x59, 0x02, // mulsd xmm0, qword ptr [rdx]
            0xf2, 0x0f, 0x58, 0xc1, // addsd xmm0, xmm1
            0xf2, 0x0f, 0x11, 0x02, // movsd qword ptr [rdx], xmm0
            0xc3, // ret
        ]);
        assert!(
            text.contains('*') && text.contains('+'),
            "the arithmetic should read as arithmetic:
{text}"
        );
        assert!(
            !text.contains("mulsd"),
            "it should not stay verbatim:
{text}"
        );
        assert!(
            text.contains("xmm"),
            "the registers say which unit this is:
{text}"
        );
    }

    #[test]
    fn a_float_compare_reaches_the_branch_that_reads_it() {
        // comisd xmm0, xmm1 ; ja +1 ; ret ; ret
        //
        // `comisd` is how a float comparison is made, so it has to leave the
        // comparison behind rather than count as flag clobber.
        let text = joined_x64(vec![
            0x66, 0x0f, 0x2f, 0xc1, // comisd xmm0, xmm1
            0x77, 0x01, // ja +1
            0xc3, // ret
            0xc3, // ret
        ]);
        assert!(
            text.contains("xmm0 >") || text.contains("xmm0 <"),
            "the branch should read the compare that set it up:
{text}"
        );
    }

    #[test]
    fn a_string_move_is_not_mistaken_for_an_sse_move() {
        // rep movsd — a block copy, which shares its mnemonic with the SSE move
        // and must not be read as an assignment.
        let text = joined_x64(vec![0xf3, 0xa5, 0xc3]);
        assert!(
            text.contains("movs"),
            "a rep-driven block copy must stay verbatim:
{text}"
        );
    }

    #[test]
    fn a_widened_negative_prints_as_one_but_a_mask_keeps_its_shape() {
        assert_eq!(render_const(0xffff_ffff_ffff_ffff), "-0x1");
        assert_eq!(render_const(0xffff_ffff_ffff_fffe), "-0x2");
        assert_eq!(render_const(0xffff_ffff_ffff_ffe0), "-0x20");
        // A 32-bit all-ones is as much a mask as it is a -1, and nothing in the
        // value says which, so it stays exactly as it was written.
        assert_eq!(render_const(0xffff_ffff), "0xffffffff");
        // A real 64-bit mask is not a small negative and keeps its shape.
        assert_eq!(render_const(0xffff_ffff_0000_0000), "0xffffffff00000000");
        assert_eq!(render_const(0x1c), "0x1c");
    }

    /// One ELF section of raw code, so the image base is zero and a table entry
    /// reads as the address it points at.
    fn lines_elf_x64(code: Vec<u8>) -> Vec<Line> {
        let va = 0x1000u64;
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let f = an.find_function(va).unwrap();
        decompile(&an, &bin, f, &BTreeMap::new(), &Db::default())
    }

    fn x64_dispatch() -> Vec<u8> {
        //   0x1000: lea r14, [rip-0x1007]        -> r14 = 0, the image base
        //   0x1007: mov ecx, [r14+rax*4+0x2000]
        //   0x100f: add rcx, r14
        //   0x1012: jmp rcx
        let mut code = vec![0u8; 0x1010];
        code[0x0000] = 0x4c;
        code[0x0001] = 0x8d;
        code[0x0002] = 0x35;
        code[0x0003..0x0007].copy_from_slice(&(-0x1007i32).to_le_bytes());
        code[0x0007] = 0x41;
        code[0x0008] = 0x8b;
        code[0x0009] = 0x8c;
        code[0x000a] = 0x86;
        code[0x000b..0x000f].copy_from_slice(&0x2000u32.to_le_bytes());
        code[0x000f] = 0x49;
        code[0x0010] = 0x03;
        code[0x0011] = 0xce;
        code[0x0012] = 0xff;
        code[0x0013] = 0xe1;
        code[0x0014] = 0xc3; // case target, 0x1014
        code[0x0015] = 0xc3; // case target, 0x1015
        code[0x1000..0x1004].copy_from_slice(&0x1014u32.to_le_bytes());
        code[0x1004..0x1008].copy_from_slice(&0x1015u32.to_le_bytes());
        code
    }

    #[test]
    fn an_x64_dispatch_reads_as_a_switch_on_the_selector() {
        let text = lines_elf_x64(x64_dispatch())
            .iter()
            .map(|l| l.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("switch (rax)"),
            "the selector is the register the table was indexed by, not the one \
             jumped through, which by then holds an address:\n{text}"
        );
        assert!(
            !text.contains("jmp rcx"),
            "the dispatch should not also stay as verbatim assembly:\n{text}"
        );
        // The load and the add are the dispatch itself. Left in, the load sits
        // above the switch writing the very register the selector names.
        assert!(
            !text.contains("+ 0x2000"),
            "the table load is mechanism, not program:\n{text}"
        );
    }

    #[test]
    fn a_case_label_states_a_position_when_no_range_check_gives_a_value() {
        // Nothing here bounds the selector, so the only thing known about a case
        // is where it sits in the table. A position is not a value, and
        // `case 0x1:` would claim the program tested for one.
        let text = lines_elf_x64(x64_dispatch())
            .iter()
            .map(|l| l.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("/* case 1 of 2 */") && text.contains("/* case 2 of 2 */"),
            "unbounded cases should read as positions:\n{text}"
        );
        assert!(
            !text.contains("case 0x0:"),
            "a table position must not be printed as a selector value:\n{text}"
        );
    }

    #[test]
    fn widening_the_accumulator_keeps_the_value_it_widened() {
        // mov eax, ecx ; cdqe ; mov [rdx], rax ; ret
        //
        // `cdqe` writes rax, so leaving it unmodelled dropped whatever rax held
        // — right where a switch is about to index a table by it.
        let text = joined_x64(vec![
            0x8b, 0xc1, // mov eax, ecx
            0x48, 0x98, // cdqe
            0x48, 0x89, 0x02, // mov [rdx], rax
            0xc3, // ret
        ]);
        assert!(
            !text.contains("cdqe"),
            "it should not stay verbatim:
{text}"
        );
        assert!(
            text.contains("ecx"),
            "the widened value should survive the widening:
{text}"
        );
    }

    #[test]
    fn a_store_feeding_an_unmodelled_instruction_is_not_dead() {
        // mov rcx, 7 ; div rcx ; ret
        //
        // Nothing the decompiler models reads rcx, so without the unmodelled
        // instruction's own reads the store looks dead and is deleted — taking
        // the divisor out of the listing.
        let code = vec![
            0x48, 0xc7, 0xc1, 0x07, 0x00, 0x00, 0x00, // mov rcx, 7
            0x48, 0xf7, 0xf1, // div rcx
            0xc3, // ret
        ];
        let text: String = lines_x64_raw(code)
            .iter()
            .map(|l| l.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("0x7"),
            "the divisor must survive dead-store elimination: {text}"
        );
    }

    /// Build a 32-bit function from raw code that supplies its own control flow
    /// and `ret`, with no appended call. For structuring tests.
    fn lines_x86_raw(code: Vec<u8>) -> Vec<Line> {
        let va = 0x1000u64;
        let mut bin = Binary::stub(Format::Pe, Arch::X86);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let f = an.find_function(va).unwrap();
        decompile(&an, &bin, f, &BTreeMap::new(), &Db::default())
    }

    /// The same, for a 64-bit PE with no import slot.
    fn lines_x64_raw(code: Vec<u8>) -> Vec<Line> {
        lines_x64_raw_with_db(code, &Db::default())
    }

    fn lines_x64_raw_with_db(code: Vec<u8>, db: &Db) -> Vec<Line> {
        let va = 0x1000u64;
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, db);
        let f = an.find_function(va).unwrap();
        decompile(&an, &bin, f, &BTreeMap::new(), db)
    }

    fn lines_x64_call(name: &str) -> Vec<Line> {
        let (va, slot) = (0x1000u64, 0x2000u64);
        // call qword ptr [rip + 0xffa] -> import slot 0x2000; ret
        let code = [0xff, 0x15, 0xfa, 0x0f, 0x00, 0x00, 0xc3];
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        bin.symbols = vec![Symbol {
            addr: slot,
            name: name.into(),
            kind: SymKind::Import,
            size: None,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let f = an.find_function(va).unwrap();
        decompile(&an, &bin, f, &BTreeMap::new(), &Db::default())
    }

    #[test]
    fn a_known_api_recovers_the_function_parameter_and_return_types() {
        let lines = lines_x64_call("strlen");
        let signature = &lines[0].text;
        assert!(
            signature.starts_with("size_t ") && signature.contains("(const char * rcx)"),
            "strlen's prototype should constrain the wrapper signature, got: {:?}",
            lines.iter().map(|line| &line.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_unknown_abi_value_stays_explicitly_pointer_sized() {
        // mov rax, rcx; ret -- there is no evidence for a narrower semantic type.
        let lines = lines_x64_raw(vec![0x48, 0x8b, 0xc1, 0xc3]);
        let signature = &lines[0].text;
        assert!(
            signature.starts_with("uintptr_t ") && signature.contains("(uintptr_t rcx)"),
            "unknown types must stay honest and ABI-sized, got: {signature}"
        );
    }

    #[test]
    fn a_user_prototype_overrides_the_recovered_signature_exactly() {
        let mut db = Db::default();
        db.set_prototype(
            0x1000,
            "bool",
            &[
                "CONTEXT *".into(),
                "const uint8_t *".into(),
                "size_t".into(),
            ],
        )
        .unwrap();
        let lines = lines_x64_raw_with_db(vec![0x48, 0x8b, 0xc1, 0xc3], &db);
        assert_eq!(
            lines[0].text,
            "bool entry(CONTEXT * rcx, const uint8_t * rdx, size_t r8) {"
        );
    }

    #[test]
    fn a_user_prototype_controls_internal_call_arity_and_return_type() {
        let va = 0x1000u64;
        // caller sets two ABI arguments; callee itself is an opaque `ret`, so
        // byte-derived analysis alone cannot recover either its arity or type.
        let mut code = vec![
            0xb9, 0x07, 0x00, 0x00, 0x00, 0xba, 0x09, 0x00, 0x00, 0x00, 0xe8, 0x11, 0x00, 0x00,
            0x00, 0xc3,
        ];
        code.resize(0x20, 0x90);
        code.push(0xc3);
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: va,
            vsize: code.len() as u64,
            file_off: va,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let mut db = Db::default();
        db.set_prototype(0x1020, "bool", &["int".into(), "size_t".into()])
            .unwrap();
        let an = engine::analyze(&bin, &bytes, 10_000, &db);
        let caller = an.find_function(va).expect("caller");
        let lines = decompile(&an, &bin, caller, &BTreeMap::new(), &db);
        let joined = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(lines[0].text.starts_with("bool entry()"), "{joined}");
        assert!(joined.contains("sub_1020(0x7, 0x9)"), "{joined}");
    }

    #[test]
    fn a_constant_pointer_offset_becomes_a_synthetic_field() {
        // mov eax,[rcx+8]; ret
        let lines = lines_x64_raw(vec![0x8b, 0x41, 0x08, 0xc3]);
        let joined = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            lines[0].text.contains("(void * rcx)"),
            "dereference use should constrain the ABI parameter: {joined}"
        );
        assert!(
            joined.contains("return rcx->field_8;"),
            "constant member displacement should become a stable field: {joined}"
        );
    }

    #[test]
    fn a_bound_user_type_replaces_the_signature_and_synthetic_field() {
        let mut db = Db::default();
        db.set_typed_field("CONTEXT", 8, "length", Some("bool"))
            .unwrap();
        db.bind_type(0x1000, "rcx", "CONTEXT").unwrap();
        let lines = lines_x64_raw_with_db(vec![0x8b, 0x41, 0x08, 0xc3], &db);
        let joined = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            lines[0].text.contains("CONTEXT * rcx"),
            "the bound type should override void *: {joined}"
        );
        assert!(
            joined.contains("rcx->length") && !joined.contains("field_8"),
            "the user field should replace the synthetic name: {joined}"
        );
        assert!(
            lines[0].text.starts_with("bool entry("),
            "the typed load should constrain the recovered return: {joined}"
        );
    }

    #[test]
    fn a_function_scoped_variable_alias_renders_without_breaking_field_facts() {
        let mut db = Db::default();
        db.set_typed_field("CONTEXT", 8, "length", Some("size_t"))
            .unwrap();
        db.bind_type(0x1000, "rcx", "CONTEXT").unwrap();
        db.set_variable(0x1000, "rcx", "request").unwrap();
        let lines = lines_x64_raw_with_db(vec![0x48, 0x8b, 0x41, 0x08, 0xc3], &db);
        let joined = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(lines[0].text.contains("CONTEXT * request"), "{joined}");
        assert!(joined.contains("request->length"), "{joined}");
        assert!(!joined.contains("rcx->"), "{joined}");
    }

    #[test]
    fn an_exact_prototype_uses_variable_aliases_for_parameter_names() {
        let mut db = Db::default();
        db.set_prototype(0x1000, "bool", &["CONTEXT *".into()])
            .unwrap();
        db.set_variable(0x1000, "rcx", "context").unwrap();
        // mov eax,ecx; ret -- the alias belongs to full rcx but should also
        // label its 32-bit use instead of mixing `context` and `ecx`.
        let lines = lines_x64_raw_with_db(vec![0x8b, 0xc1, 0xc3], &db);
        assert_eq!(lines[0].text, "bool entry(CONTEXT * context) {");
        assert!(
            lines
                .iter()
                .any(|line| line.text.contains("return context")),
            "the alias should label the returned value: {lines:?}"
        );
    }

    #[test]
    fn a_constant_pointer_store_uses_the_same_field_notation() {
        // mov [rcx+10h],edx; ret
        let joined = lines_x64_raw(vec![0x89, 0x51, 0x10, 0xc3])
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("rcx->field_10 = edx;"),
            "field writes should match field reads: {joined}"
        );
    }

    #[test]
    fn indexed_memory_stays_exact_pointer_arithmetic() {
        // mov eax,[rcx+rdx*4+8]; ret
        let lines = lines_x64_raw(vec![0x8b, 0x44, 0x91, 0x08, 0xc3]);
        let joined = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("rdx * 0x4"),
            "the scaled index must survive: {joined}"
        );
        assert!(
            !joined.contains("field_8"),
            "an indexed address is not enough evidence for an aggregate field: {joined}"
        );
        assert!(
            lines[0].text.contains("void * rcx") && lines[0].text.contains("uintptr_t rdx"),
            "only the address base should become a pointer: {joined}"
        );
    }

    #[test]
    fn a_negative_pointer_offset_has_an_unambiguous_field_name() {
        // mov eax,[rcx-8]; ret
        let joined = lines_x64_raw(vec![0x8b, 0x41, 0xf8, 0xc3])
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("rcx->field_m8"),
            "negative offsets need a stable name: {joined}"
        );
    }

    #[test]
    fn a_local_used_as_a_field_base_becomes_a_pointer() {
        let blocks = [IrBlock {
            start: 0x1000,
            stmts: vec![Stmt::Ret(Some(Expr::Mem(Box::new(Expr::Bin(
                "+",
                Box::new(Expr::Mem(Box::new(Expr::Stack(-8)))),
                Box::new(Expr::Const(8)),
            )))))],
            succ: Vec::new(),
        }];
        assert_eq!(
            local_declarations(&blocks, &BTreeMap::new(), &Db::default(), 0),
            vec!["void * var_8;"]
        );
    }

    #[test]
    fn x64_rsp_locals_are_named_and_the_prologue_is_dropped() {
        // The MSVC x64 shape: mov rax,rsp; save a register through it; allocate a
        // frame; then read an argument and write a local off rsp.
        let code = vec![
            0x48, 0x8b, 0xc4, // mov rax, rsp        (frame-base alias)
            0x48, 0x89, 0x58, 0x08, // mov [rax+8], rbx   (nonvolatile spill)
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28      (frame allocation)
            0x89, 0x54, 0x24, 0x20, // mov [rsp+0x20], edx  -> var_8
            0x8b, 0x44, 0x24, 0x30, // mov eax, [rsp+0x30]  -> arg_8 (returned)
            0xc3, // ret
        ];
        let joined = lines_x64_raw(code)
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("return arg_8;") && joined.contains("var_8 = edx;"),
            "rsp-relative locals should be named, got:\n{joined}"
        );
        for gone in ["rax = rsp", "= rbx", "rsp -", "*(rsp"] {
            assert!(
                !joined.contains(gone),
                "stack bookkeeping `{gone}` should be gone, got:\n{joined}"
            );
        }
    }

    #[test]
    fn setcc_becomes_a_boolean_comparison() {
        // cmp ecx,edx ; sete al ; movzx eax,al ; ret
        let code = vec![
            0x39, 0xd1, // cmp ecx, edx
            0x0f, 0x94, 0xc0, // sete al
            0x0f, 0xb6, 0xc0, // movzx eax, al
            0xc3, // ret
        ];
        let joined = lines_x86_raw(code)
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("ecx == edx"),
            "setcc should recover the comparison, got:\n{joined}"
        );
        assert!(!joined.contains("sete"), "no raw setcc, got:\n{joined}");
    }

    #[test]
    fn cmov_becomes_a_ternary() {
        // cmp rax,rbx ; cmove rax,rcx ; ret
        let code = vec![
            0x48, 0x39, 0xd8, // cmp rax, rbx
            0x48, 0x0f, 0x44, 0xc1, // cmove rax, rcx
            0xc3, // ret
        ];
        let joined = lines_x64_raw(code)
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("rax == rbx ? rcx :"),
            "cmov should read as a ternary, got:\n{joined}"
        );
        assert!(!joined.contains("cmov"), "no raw cmov, got:\n{joined}");
    }

    #[test]
    fn a_pushed_string_address_reads_as_the_literal_32bit() {
        // push 0x2000 ; call puts ; where "hi!" lives at 0x2000.
        let va = 0x1000u64;
        let (slot, sink) = (0x4000u64, "puts");
        let mut bin = Binary::stub(Format::Pe, Arch::X86);
        bin.entry = va;
        bin.image_base = 0;
        bin.sections = vec![
            Section {
                name: ".text".into(),
                vaddr: va,
                vsize: 16,
                file_off: va,
                file_size: 16,
                entropy: 0.0,
                read: true,
                write: false,
                exec: true,
            },
            Section {
                name: ".rdata".into(),
                vaddr: 0x2000,
                vsize: 8,
                file_off: 0x2000,
                file_size: 8,
                entropy: 0.0,
                read: true,
                write: false,
                exec: false,
            },
        ];
        bin.symbols = vec![Symbol {
            addr: slot,
            name: sink.into(),
            kind: SymKind::Import,
            size: None,
        }];
        let mut bytes = vec![0u8; 0x2008];
        // 0x1000: push 0x2000 ; call [0x4000] ; ret
        bytes[0x1000..0x100c].copy_from_slice(&[
            0x68, 0x00, 0x20, 0x00, 0x00, // push 0x2000
            0xff, 0x15, 0x00, 0x40, 0x00, 0x00, // call dword [0x4000]
            0xc3, // ret
        ]);
        bytes[0x2000..0x2008].copy_from_slice(b"cmd.exe\0");
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let strings = crate::listing::string_map(&bin, &bytes, engine::display_base(&bin));
        let f = an.find_function(va).unwrap();
        let joined = decompile(&an, &bin, f, &strings, &Db::default())
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("puts(\"cmd.exe\")"),
            "a pushed string pointer should read as the text, got:\n{joined}"
        );
    }

    #[test]
    fn a_pointer_to_a_string_reads_as_the_literal() {
        // lea rax, [rip+0xff9] -> 0x2000, where "cmd.exe" lives; ret.
        let va = 0x1000u64;
        let mut bin = Binary::stub(Format::Pe, Arch::X86_64);
        bin.entry = va;
        bin.sections = vec![
            Section {
                name: ".text".into(),
                vaddr: va,
                vsize: 8,
                file_off: va,
                file_size: 8,
                entropy: 0.0,
                read: true,
                write: false,
                exec: true,
            },
            Section {
                name: ".rdata".into(),
                vaddr: 0x2000,
                vsize: 8,
                file_off: 0x2000,
                file_size: 8,
                entropy: 0.0,
                read: true,
                write: false,
                exec: false,
            },
        ];
        let mut bytes = vec![0u8; 0x2008];
        bytes[0x1000..0x1008].copy_from_slice(&[0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0xc3]);
        bytes[0x2000..0x2008].copy_from_slice(b"cmd.exe\0");
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let strings = crate::listing::string_map(&bin, &bytes, 0);
        let f = an.find_function(va).unwrap();
        let joined = decompile(&an, &bin, f, &strings, &Db::default())
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("\"cmd.exe\""),
            "a pointer into a string should read as the quoted text, got:\n{joined}"
        );
    }

    #[test]
    fn frame_slots_are_named_and_housekeeping_is_dropped() {
        // A real prologue/epilogue with a frame local and an argument:
        //   push ebp; mov ebp,esp; sub esp,0x10
        //   mov eax,[ebp+8]; mov [ebp-4],eax
        //   leave; ret
        let code = vec![
            0x55, // push ebp
            0x89, 0xe5, // mov ebp, esp
            0x83, 0xec, 0x10, // sub esp, 0x10
            0x8b, 0x45, 0x08, // mov eax, [ebp+8]
            0x89, 0x45, 0xfc, // mov [ebp-4], eax
            0xc9, // leave
            0xc3, // ret
        ];
        let text: Vec<String> = lines_x86_raw(code).into_iter().map(|l| l.text).collect();
        let joined = text.join("\n");
        // The local and the argument read as named frame slots.
        assert!(
            joined.contains("var_4 = arg_8;"),
            "frame slots should be named, got:\n{joined}"
        );
        // The prologue, frame setup, and epilogue are gone: no esp/ebp
        // bookkeeping, no `leave`, and no raw `*(ebp ...)` frame reference.
        for noise in ["esp", "ebp", "leave"] {
            assert!(
                !joined.contains(noise),
                "housekeeping `{noise}` should be dropped, got:\n{joined}"
            );
        }
    }

    #[test]
    fn an_arithmetic_flag_becomes_a_real_comparison() {
        // mov eax,[ebp+8]; sub eax,5; je else; mov eax,1; jmp end; else: mov eax,2; end: ret
        // The `sub` sets the flags the `je` reads; the branch must become a
        // comparison against zero, not an opaque `flags` test.
        let code = vec![
            0x8b, 0x45, 0x08, // mov eax, [ebp+8]
            0x2d, 0x05, 0x00, 0x00, 0x00, // sub eax, 5
            0x74, 0x07, // je +7 -> else
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xeb, 0x05, // jmp +5 -> end
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2  (else)
            0xc3, // ret
        ];
        let joined = lines_x86_raw(code)
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("if (eax == 0x0) {"),
            "the sub/je pair should recover a comparison, got:\n{joined}"
        );
        assert!(
            !joined.contains("flags"),
            "no opaque flags condition should remain, got:\n{joined}"
        );
    }

    #[test]
    fn a_bottom_tested_loop_keeps_its_body_inside() {
        // mov ecx,0xa; loop: dec ecx; jnz loop; ret
        // The header does the decrement each iteration, so it must stay inside
        // the loop (an infinite loop with a break), not be hoisted out.
        let code = vec![
            0xb9, 0x0a, 0x00, 0x00, 0x00, // mov ecx, 0xa
            0x49, // dec ecx
            0x75, 0xfd, // jnz -3 -> dec
            0xc3, // ret
        ];
        let text: Vec<String> = lines_x86_raw(code).into_iter().map(|l| l.text).collect();
        let joined = text.join("\n");
        assert!(
            joined.contains("while (1) {"),
            "a self-loop header becomes an infinite loop, got:\n{joined}"
        );
        assert!(
            joined.contains("ecx--;") && joined.contains("if (ecx == 0x0) break;"),
            "the decrement stays in the loop with a break on exit, got:\n{joined}"
        );
        // The decrement appears once (inside the loop), not hoisted out as well.
        assert_eq!(
            text.iter().filter(|l| l.contains("ecx--;")).count(),
            1,
            "the loop body must not be duplicated, got:\n{joined}"
        );
    }

    #[test]
    fn a_fixed_address_becomes_a_named_global() {
        // mov dword [0x9000], 0x2a ; mov eax, [0x9000] ; ret
        // An absolute memory operand is an anonymous global, so it reads as
        // `g_9000`, not `*(0x9000)`.
        let code = vec![
            0xc7, 0x05, 0x00, 0x90, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov [0x9000], 0x2a
            0x8b, 0x05, 0x00, 0x90, 0x00, 0x00, // mov eax, [0x9000]
            0xc3, // ret
        ];
        let joined = lines_x86_raw(code)
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("g_9000 = 0x2a;") && joined.contains("return g_9000;"),
            "a fixed address should read as g_9000, got:\n{joined}"
        );
        assert!(
            !joined.contains("*(0x9000)") && !joined.contains("*(g_9000)"),
            "the raw dereference should be gone, got:\n{joined}"
        );
    }

    #[test]
    fn a_jump_table_becomes_a_switch() {
        // mov eax,[ebp+8]; jmp [eax*4 + table]; three cases each returning a
        // constant; then the table of their addresses.
        let code = vec![
            0x8b, 0x45, 0x08, // 0x1000 mov eax, [ebp+8]
            0xff, 0x24, 0x85, 0x1c, 0x10, 0x00, 0x00, // 0x1003 jmp [eax*4 + 0x101c]
            0xb8, 0xaa, 0x00, 0x00, 0x00, 0xc3, // 0x100a case0: mov eax,0xaa; ret
            0xb8, 0xbb, 0x00, 0x00, 0x00, 0xc3, // 0x1010 case1: mov eax,0xbb; ret
            0xb8, 0xcc, 0x00, 0x00, 0x00, 0xc3, // 0x1016 case2: mov eax,0xcc; ret
            0x0a, 0x10, 0x00, 0x00, // 0x101c table[0] = 0x100a
            0x10, 0x10, 0x00, 0x00, // table[1] = 0x1010
            0x16, 0x10, 0x00, 0x00, // table[2] = 0x1016
        ];
        let joined = lines_x86_raw(code)
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("switch ("),
            "an indexed jump should become a switch, got:\n{joined}"
        );
        // Nothing in this fixture bounds the selector, so the cases are known
        // by position and not by value. They used to print as `case 0x0:`,
        // which states that the program tested the selector against zero. It
        // was the index into the table, and the two are only the same number
        // when the switch happens to start there.
        for (case, val) in [
            ("/* case 1 of 3 */", "0xaa"),
            ("/* case 2 of 3 */", "0xbb"),
            ("/* case 3 of 3 */", "0xcc"),
        ] {
            assert!(
                joined.contains(case) && joined.contains(val),
                "case {case} with body {val} should be recovered, got:\n{joined}"
            );
        }
        assert!(
            !joined.contains("case 0x"),
            "a table position must not be printed as a selector value:\n{joined}"
        );
    }

    #[test]
    fn an_if_else_is_structured() {
        // cmp [ebp+8],0 ; je else ; mov eax,1 ; jmp end ; else: mov eax,2 ; end: ret
        // Two arms that reconverge at the return: this must become a real
        // if/else, not a goto chain.
        let code = vec![
            0x83, 0x7d, 0x08, 0x00, // cmp dword [ebp+8], 0
            0x74, 0x07, // je +7  -> else block
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xeb, 0x05, // jmp +5 -> end
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2   (else)
            0xc3, // ret
        ];
        let text: Vec<String> = lines_x86_raw(code).into_iter().map(|l| l.text).collect();
        let joined = text.join("\n");
        assert!(
            joined.contains("if (*(ebp + 0x8) == 0x0) {") && joined.contains("} else {"),
            "expected a structured if/else, got:\n{joined}"
        );
        // Structured output never falls back to labels or gotos.
        assert!(
            !joined.contains("goto") && !text.iter().any(|l| l.ends_with(':')),
            "structured output must be goto-free, got:\n{joined}"
        );
    }

    #[test]
    fn a_counting_loop_is_structured() {
        // mov eax,0 ; head: cmp eax,0xa ; jge end ; add eax,1 ; jmp head ; end: ret
        // The back edge must be recovered as a `while`, with the exit block as
        // the loop follow even though the header dominates it.
        let code = vec![
            0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0x83, 0xf8, 0x0a, // cmp eax, 0xa   (header)
            0x7d, 0x05, // jge +5 -> end
            0x83, 0xc0, 0x01, // add eax, 1
            0xeb, 0xf6, // jmp -10 -> header
            0xc3, // ret
        ];
        let text: Vec<String> = lines_x86_raw(code).into_iter().map(|l| l.text).collect();
        let joined = text.join("\n");
        assert!(
            joined.contains("while (eax < 0xa) {"),
            "expected a structured while loop, got:\n{joined}"
        );
        assert!(
            !joined.contains("goto") && !text.iter().any(|l| l.ends_with(':')),
            "structured output must be goto-free, got:\n{joined}"
        );
    }

    #[test]
    fn a_value_used_in_a_later_block_is_not_deleted() {
        // eax = 0x7 ; jmp +0 ; (next block) push eax ; call puts
        // The def of eax is in the first block, its use in the second. Liveness
        // is a whole-function dataflow, so dead-store elimination must keep the
        // def even though nothing in its own block reads it.
        let code = vec![
            0xb8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
            0xeb, 0x00, // jmp +0
            0x50, // push eax
        ];
        let lines = lines_x86("puts", code);
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        // Cross-block propagation carries eax = 7 from the first block into the
        // call in the second, and dead-store elimination then removes the now
        // unused definition.
        assert!(
            text.iter().any(|s| s.contains("puts(0x7)")),
            "the constant flows across the block boundary: {text:?}"
        );
        assert!(
            !text.iter().any(|s| s.contains("eax = 0x7;")),
            "and its now-dead definition is removed: {text:?}"
        );
    }

    #[test]
    fn a_value_defined_on_both_arms_survives_the_join() {
        // cmp [ebp+8],0 ; je else ; mov eax,7 ; jmp end ; else: mov eax,7 ;
        // end: push eax ; call puts
        // Both arms of the if/else set eax to the same constant. The merge rule
        // must keep it across the join, so the call renders with the constant
        // propagated in rather than a bare register.
        let code = vec![
            0x83, 0x7d, 0x08, 0x00, // cmp dword [ebp+8], 0
            0x74, 0x07, // je +7  -> else
            0xb8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
            0xeb, 0x05, // jmp +5 -> end
            0xb8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7   (else)
            0x50, // push eax
        ];
        let lines = lines_x86("puts", code);
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert!(
            text.iter().any(|s| s.contains("puts(0x7)")),
            "the constant defined on both arms flows through the join: {text:?}"
        );
    }

    #[test]
    fn differing_values_on_two_arms_become_a_conditional_value() {
        // cmp [ebp+8],0 ; je else ; mov eax,7 ; jmp end ; else: mov eax,9 ;
        // end: push eax ; call puts. A conservative merge used to discard eax
        // here. Preserve both reaching definitions explicitly instead.
        let code = vec![
            0x83, 0x7d, 0x08, 0x00, // cmp dword [ebp+8], 0
            0x74, 0x07, // je +7  -> else
            0xb8, 0x07, 0x00, 0x00, 0x00, // mov eax, 7
            0xeb, 0x05, // jmp +5 -> end
            0xb8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9   (else)
            0x50, // push eax
        ];
        let lines = lines_x86("puts", code);
        let text: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert!(
            text.iter()
                .any(|line| line.contains("puts(") && line.contains("? 0x9 : 0x7")),
            "the controlling branch should select both reaching values: {text:?}"
        );
        assert!(
            text.iter().all(|line| !line.contains("phi(")),
            "a provable direct diamond should lower to C syntax: {text:?}"
        );
    }
}
