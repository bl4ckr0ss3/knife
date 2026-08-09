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
//! It is still not a full decompiler: there is no type recovery, and control
//! flow is rendered as `if`/`goto` over the recovered labels rather than
//! reconstructed loops. The honest rule holds throughout: an instruction the
//! lifter does not model becomes an opaque `asm(...)` statement, never a guess.

use crate::analysis::engine::{Analysis, Function};
use crate::model::{Binary, Format};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};
use std::collections::{BTreeMap, BTreeSet};

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
    Bin(&'static str, Box<Expr>, Box<Expr>),
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
    /// Verbatim assembly for an unmodelled instruction.
    Asm(String),
}

/// A block of lifted statements with its address and successors.
struct IrBlock {
    start: u64,
    stmts: Vec<Stmt>,
    succ: Vec<u64>,
}

/// One rendered output line.
#[derive(Debug, Clone)]
pub struct Line {
    pub label: bool,
    pub text: String,
}

// ── entry point ───────────────────────────────────────────────────────────

/// Decompile a recovered function to pseudocode lines.
pub fn decompile(an: &Analysis, bin: &Binary, f: &Function) -> Vec<Line> {
    let win64 = bin.format == Format::Pe && an.bits == 64;

    // Predecessor counts (by block index), so a block with a single predecessor
    // can inherit that predecessor's propagation state.
    let idx: BTreeMap<u64, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start, i))
        .collect();
    let mut preds: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); f.blocks.len()];
    for (i, b) in f.blocks.iter().enumerate() {
        for s in &b.succ {
            if let Some(&j) = idx.get(s) {
                preds[j].insert(i);
            }
        }
    }

    // Lift in address order, carrying each block's exit register state forward.
    // A block whose only predecessor was already lifted starts from that
    // predecessor's exit state, so a constant or expression set in one block
    // flows into the next. Merges and back edges start fresh, which is the safe
    // choice: a value that arrives on only one path must not be assumed.
    let mut exit: Vec<BTreeMap<Register, Expr>> = vec![BTreeMap::new(); f.blocks.len()];
    let mut blocks: Vec<IrBlock> = Vec::with_capacity(f.blocks.len());
    for (i, b) in f.blocks.iter().enumerate() {
        // Inherit only from a single predecessor that was already lifted; a
        // merge point or a back edge starts fresh.
        let entry = match preds[i].iter().copied().collect::<Vec<_>>().as_slice() {
            [p] if *p < i => exit[*p].clone(),
            _ => BTreeMap::new(),
        };
        let (stmts, exit_state) = lift_block(b, an, bin, win64, entry);
        exit[i] = exit_state;
        blocks.push(IrBlock {
            start: b.start,
            stmts,
            succ: b.succ.clone(),
        });
    }

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

    render(an, f, &blocks)
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
#[derive(Default)]
struct Lift {
    regs: BTreeMap<Register, Expr>,
    /// Arguments pushed since the last call, in program order (32-bit calls).
    pushed: Vec<Expr>,
    /// Operands of the last `cmp`/`test`, for the next conditional branch.
    cmp: Option<(Expr, Expr, bool)>,
}

fn lift_block(
    b: &crate::analysis::engine::BasicBlock,
    an: &Analysis,
    bin: &Binary,
    win64: bool,
    entry: BTreeMap<Register, Expr>,
) -> (Vec<Stmt>, BTreeMap<Register, Expr>) {
    let mut st = Lift {
        regs: entry,
        ..Default::default()
    };
    let mut out = Vec::new();
    for ins in &b.insns {
        let Some(d) = decode(&ins.bytes, ins.addr, an.bits) else {
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
        );
    }
    (out, st.regs)
}

fn reg(r: Register) -> Expr {
    Expr::Reg(r.full_register(), r)
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

/// The address expression of a memory operand (no dereference), substituted.
fn mem_addr(d: &Instruction, st: &Lift) -> Expr {
    if d.is_ip_rel_memory_operand() {
        return Expr::Const(d.ip_rel_memory_address());
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
    // 32-bit displacements are zero-extended by iced; sign-extend so a frame
    // offset reads as `- 0x28`, not a huge positive constant.
    let raw = d.memory_displacement64();
    let disp = if raw <= 0xffff_ffff && raw & 0x8000_0000 != 0 {
        i64::from(raw as u32 as i32)
    } else {
        raw as i64
    };
    match acc {
        None => Expr::Const(disp as u64),
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

#[allow(clippy::too_many_arguments)]
fn lift_insn(
    d: &Instruction,
    st: &mut Lift,
    an: &Analysis,
    bin: &Binary,
    win64: bool,
    target_name: Option<&str>,
    out: &mut Vec<Stmt>,
) {
    use Mnemonic::*;
    let binset = |st: &Lift, op: &'static str| {
        Stmt::Set(
            dest(d, st),
            Expr::Bin(op, Box::new(operand(d, st, 0)), Box::new(operand(d, st, 1))),
        )
    };
    // Build the statement (reading the current register expressions), then
    // update the propagation state from it. Pushes and compares update state
    // directly and emit nothing.
    let stmt: Option<Stmt> = match d.mnemonic() {
        Nop | Endbr32 | Endbr64 => None,
        Mov | Movzx | Movsx | Movsxd => Some(Stmt::Set(dest(d, st), operand(d, st, 1))),
        Lea => Some(Stmt::Set(
            dest(d, st),
            Expr::Addr(Box::new(mem_addr(d, st))),
        )),
        Add => Some(binset(st, "+")),
        Sub => Some(binset(st, "-")),
        And => Some(binset(st, "&")),
        Or => Some(binset(st, "|")),
        Shl | Sal => Some(binset(st, "<<")),
        Shr | Sar => Some(binset(st, ">>")),
        Imul if d.op_count() >= 2 => Some(binset(st, "*")),
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
        Inc => Some(Stmt::Set(
            dest(d, st),
            Expr::Bin("+", Box::new(operand(d, st, 0)), Box::new(Expr::Const(1))),
        )),
        Dec => Some(Stmt::Set(
            dest(d, st),
            Expr::Bin("-", Box::new(operand(d, st, 0)), Box::new(Expr::Const(1))),
        )),
        Push => {
            let a = operand(d, st, 0);
            st.pushed.push(a);
            None
        }
        Pop => Some(Stmt::Set(dest(d, st), Expr::Opaque("pop()".into()))),
        Cmp => {
            st.cmp = Some((operand(d, st, 0), operand(d, st, 1), false));
            None
        }
        Test => {
            st.cmp = Some((operand(d, st, 0), operand(d, st, 1), true));
            None
        }
        Call => {
            let call = lift_call(d, st, an, bin, win64, target_name);
            let ret = if an.bits == 32 {
                Register::EAX
            } else {
                Register::RAX
            };
            Some(Stmt::Set(reg(ret), call))
        }
        Ret => Some(Stmt::Ret(Some(reg(if an.bits == 32 {
            Register::EAX
        } else {
            Register::RAX
        })))),
        Jmp => Some(match branch_target(d) {
            Some(t) => Stmt::Goto(t),
            None => Stmt::Asm(raw(d)),
        }),
        m if is_jcc(m) => Some(match branch_target(d) {
            Some(t) => Stmt::Branch(condition(m, &st.cmp), t),
            None => Stmt::Asm(raw(d)),
        }),
        _ => Some(Stmt::Asm(raw(d))),
    };

    if let Some(s) = stmt {
        update_state(st, &s);
        out.push(s);
    }
}

/// Update the propagation state from an emitted statement: remember a register's
/// new pure value, forget it otherwise, and drop memory-reading values whenever
/// a store or call could have changed memory.
fn update_state(st: &mut Lift, s: &Stmt) {
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
        if is_pure(src) {
            st.regs.insert(*root, src.clone());
        } else {
            st.regs.remove(root);
        }
    }
}

fn lift_call(
    d: &Instruction,
    st: &mut Lift,
    an: &Analysis,
    bin: &Binary,
    win64: bool,
    target_name: Option<&str>,
) -> Expr {
    let name = target_name
        .map(strip_module)
        .or_else(|| call_target(d, an, bin).map(|t| an.label(t)))
        .unwrap_or_else(|| "sub".to_string());

    let args = if an.bits == 32 {
        // Right-to-left pushes: reverse to C order; whatever was pushed since the
        // last call is the argument list. Each was snapshotted at its push.
        let mut a = std::mem::take(&mut st.pushed);
        a.reverse();
        a
    } else {
        st.pushed.clear();
        let n = arity(&name).unwrap_or(0);
        arg_registers(win64)
            .iter()
            .take(n)
            .map(|&r| reg_val(st, r))
            .collect()
    };
    st.pushed.clear();
    Expr::Call(name, args)
}

fn is_pure(e: &Expr) -> bool {
    match e {
        Expr::Const(_) | Expr::Reg(..) => true,
        Expr::Mem(a) | Expr::Addr(a) => is_pure(a),
        Expr::Bin(_, l, r) => is_pure(l) && is_pure(r),
        // A call is never pure; an opaque value is not safe to duplicate.
        Expr::Call(..) | Expr::Opaque(_) => false,
    }
}

fn reads_mem(e: &Expr) -> bool {
    match e {
        Expr::Mem(_) => true,
        Expr::Addr(a) => reads_mem(a),
        Expr::Bin(_, l, r) => reads_mem(l) || reads_mem(r),
        Expr::Call(_, args) => args.iter().any(reads_mem),
        Expr::Const(_) | Expr::Reg(..) | Expr::Opaque(_) => false,
    }
}

fn contains_call(e: &Expr) -> bool {
    match e {
        Expr::Call(..) => true,
        Expr::Mem(a) | Expr::Addr(a) => contains_call(a),
        Expr::Bin(_, l, r) => contains_call(l) || contains_call(r),
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
        Stmt::CallVoid(e) | Stmt::Branch(e, _) | Stmt::Ret(Some(e)) => reads_regs(e, live),
        _ => {}
    }
}

fn reads_regs(e: &Expr, live: &mut BTreeSet<Register>) {
    match e {
        Expr::Reg(root, _) => {
            live.insert(*root);
        }
        Expr::Mem(a) | Expr::Addr(a) => reads_regs(a, live),
        Expr::Bin(_, l, r) => {
            reads_regs(l, live);
            reads_regs(r, live);
        }
        Expr::Call(_, args) => args.iter().for_each(|a| reads_regs(a, live)),
        Expr::Const(_) | Expr::Opaque(_) => {}
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
        Stmt::CallVoid(e) | Stmt::Branch(e, _) | Stmt::Ret(Some(e)) => fold(e),
        _ => {}
    }
}

fn fold(e: &mut Expr) {
    match e {
        Expr::Mem(a) | Expr::Addr(a) => fold(a),
        Expr::Bin(op, l, r) => {
            fold(l);
            fold(r);
            if let (Expr::Const(a), Expr::Const(b)) = (l.as_ref(), r.as_ref()) {
                if let Some(v) = eval(op, *a, *b) {
                    *e = Expr::Const(v);
                }
            }
        }
        Expr::Call(_, args) => args.iter_mut().for_each(fold),
        Expr::Const(_) | Expr::Reg(..) | Expr::Opaque(_) => {}
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

fn render(an: &Analysis, f: &Function, blocks: &[IrBlock]) -> Vec<Line> {
    let base = an.display_base;
    let mut out = vec![Line {
        label: true,
        text: format!("sub_{:x}() {{", f.addr + base),
    }];
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
                text: render_stmt(s, base),
            });
        }
    }
    out.push(Line {
        label: true,
        text: "}".to_string(),
    });
    out
}

fn render_stmt(s: &Stmt, base: u64) -> String {
    match s {
        Stmt::Set(dst, src) => format!("{} = {};", render_expr(dst), render_expr(src)),
        Stmt::CallVoid(e) => format!("{};", render_expr(e)),
        Stmt::Ret(Some(e)) => format!("return {};", render_expr(e)),
        Stmt::Ret(None) => "return;".to_string(),
        Stmt::Branch(c, t) => format!("if ({}) goto loc_{:x};", render_expr(c), t + base),
        Stmt::Goto(t) => format!("goto loc_{:x};", t + base),
        Stmt::Asm(s) => format!("/* {s} */"),
    }
}

fn render_expr(e: &Expr) -> String {
    match e {
        Expr::Const(v) => format!("0x{v:x}"),
        Expr::Reg(_, shown) => format!("{shown:?}").to_lowercase(),
        Expr::Mem(a) => format!("*({})", render_expr(a)),
        Expr::Addr(a) => format!("&({})", render_expr(a)),
        Expr::Bin(op, l, r) => format!("{} {op} {}", render_expr(l), render_expr(r)),
        Expr::Call(name, args) => {
            let a: Vec<String> = args.iter().map(render_expr).collect();
            format!("{name}({})", a.join(", "))
        }
        Expr::Opaque(s) => s.clone(),
    }
}

// ── small helpers ─────────────────────────────────────────────────────────

fn raw(d: &Instruction) -> String {
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_uppercase_hex(false);
    fmt.options_mut().set_hex_prefix("0x");
    fmt.options_mut().set_hex_suffix("");
    let mut s = String::new();
    fmt.format(d, &mut s);
    s
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

fn condition(m: Mnemonic, cmp: &Option<(Expr, Expr, bool)>) -> Expr {
    let (l, r, was_test) = match cmp {
        Some(c) => c.clone(),
        None => (Expr::Opaque("flags".into()), Expr::Const(0), false),
    };
    let op = match m {
        Mnemonic::Je => "==",
        Mnemonic::Jne => "!=",
        Mnemonic::Jg | Mnemonic::Ja => ">",
        Mnemonic::Jge | Mnemonic::Jae => ">=",
        Mnemonic::Jl | Mnemonic::Jb => "<",
        Mnemonic::Jle | Mnemonic::Jbe => "<=",
        _ => return Expr::Opaque(format!("{m:?}").to_lowercase()),
    };
    // `test x, x; je` means x == 0.
    if was_test {
        let op = if m == Mnemonic::Je { "==" } else { "!=" };
        return Expr::Bin(op, Box::new(l), Box::new(Expr::Const(0)));
    }
    Expr::Bin(op, Box::new(l), Box::new(r))
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
    Some(match bare {
        "malloc" | "free" | "atoi" | "puts" | "strlen" | "system" => 1,
        "strcpy" | "strcat" | "lstrcpyA" | "lstrcpyW" | "lstrcatA" | "lstrcatW" => 2,
        "memcpy" | "memmove" | "memset" | "strncpy" | "strncat" | "snprintf" => 3,
        _ => return None,
    })
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
        }];
        let mut bytes = vec![0u8; va as usize];
        bytes.extend_from_slice(&code);
        let an = engine::analyze(&bin, &bytes, 10_000, &Db::default());
        let f = an.find_function(va).unwrap();
        decompile(&an, &bin, f)
    }

    #[test]
    fn dead_intermediate_assignments_are_removed() {
        // mov eax,[ebp+8]; add eax,0x1c; push eax; lea eax,[ebp-0x28]; push eax; call
        // The two eax computations feed the call and are dead afterward, so only
        // the call statement should survive.
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
                .any(|s| s.contains("lstrcpyA(&(ebp - 0x28), *(ebp + 0x8) + 0x1c)")),
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

    #[test]
    fn an_unmodelled_instruction_stays_verbatim() {
        let lines = lines_x86("puts", vec![0x0f, 0xa2]); // cpuid
        assert!(lines
            .iter()
            .any(|l| l.text.contains("/*") && l.text.contains("cpuid")));
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
}
