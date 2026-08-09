//! A pseudocode view: the closest knife comes to a decompiler, and honest about
//! the distance.
//!
//! This is not a decompiler. It does no type recovery, no cross-block value
//! flow, and no control-flow structuring beyond the labels and gotos the engine
//! already recovered. What it does is lift each instruction to a C-like
//! statement and propagate expressions **within a basic block**, so a run of
//! `mov`/`lea`/`add` collapses into the expression it computes and a call shows
//! its arguments instead of the pushes that set them up. On a stripped 32-bit
//! binary that turns the six instructions of a stack overflow into one readable
//! line, `lstrcpyA(ebp - 0x28, *(ebp + 8) + 0x1c)`, which is the whole point.
//!
//! The rule is the same one the rest of the tool follows: never invent. An
//! instruction the lifter does not model is emitted verbatim as `/* asm */`, so
//! the reader always knows where the clean lift stops.

use crate::analysis::engine::{Analysis, Function};
use crate::model::{Binary, Format};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};
use std::collections::HashMap;

/// One rendered line: a block label (or brace/signature) or a statement.
#[derive(Debug, Clone)]
pub struct Line {
    pub label: bool,
    pub text: String,
}

/// Lift a recovered function into pseudocode lines.
pub fn function(an: &Analysis, bin: &Binary, f: &Function) -> Vec<Line> {
    let win64 = bin.format == Format::Pe && an.bits == 64;
    let mut out = Vec::new();

    // A signature line, so the reader knows what they are looking at.
    out.push(Line {
        label: true,
        text: format!("sub_{:x}() {{", f.addr + an.display_base),
    });

    for (bi, block) in f.blocks.iter().enumerate() {
        if bi > 0 {
            out.push(Line {
                label: true,
                text: format!("loc_{:x}:", block.start + an.display_base),
            });
        }

        // Expression state is per block: values do not flow across a block
        // boundary here, which keeps the output honest rather than guessing at
        // what a predecessor left in a register.
        let mut st = State::default();

        for ins in &block.insns {
            let Some(d) = decode(&ins.bytes, ins.addr, an.bits) else {
                continue;
            };
            if let Some(stmt) = lift(&d, &mut st, an, bin, win64, ins.target_name.as_deref()) {
                out.push(Line {
                    label: false,
                    text: stmt,
                });
            }
        }
    }

    out.push(Line {
        label: true,
        text: "}".to_string(),
    });
    out
}

/// Per-block lifter state.
#[derive(Default)]
struct State {
    /// 64-bit register root -> its current expression.
    regs: HashMap<Register, String>,
    /// Arguments pushed since the last call, newest first (32-bit calls).
    pushed: Vec<String>,
    /// The operands of the last `cmp`/`test`, for the next conditional branch.
    last_cmp: Option<(String, String, bool)>, // (lhs, rhs, was_test)
}

fn decode(raw: &[u8], ip: u64, bits: u32) -> Option<Instruction> {
    if raw.is_empty() {
        return None;
    }
    let mut dec = Decoder::with_ip(bits, raw, ip, DecoderOptions::NONE);
    dec.can_decode()
        .then(|| dec.decode())
        .filter(|i| !i.is_invalid())
}

fn reg_name(r: Register) -> String {
    format!("{r:?}").to_lowercase()
}

/// The expression currently held in a register, or its name if unknown.
fn reg_expr(st: &State, r: Register) -> String {
    if r == Register::None {
        return String::new();
    }
    st.regs
        .get(&r.full_register())
        .cloned()
        .unwrap_or_else(|| reg_name(r))
}

/// Render a memory operand. `deref` wraps it in a load; lea wants the address.
fn mem_expr(d: &Instruction, st: &State, deref: bool) -> String {
    // A rip-relative operand resolves to a fixed address the engine can name.
    if d.is_ip_rel_memory_operand() {
        let a = d.ip_rel_memory_address();
        return if deref {
            format!("*(0x{a:x})")
        } else {
            format!("0x{a:x}")
        };
    }

    let mut parts: Vec<String> = Vec::new();
    let base = d.memory_base();
    if base != Register::None {
        parts.push(reg_expr(st, base));
    }
    let index = d.memory_index();
    if index != Register::None {
        let scale = d.memory_index_scale();
        if scale > 1 {
            parts.push(format!("{}*{}", reg_expr(st, index), scale));
        } else {
            parts.push(reg_expr(st, index));
        }
    }
    // A 32-bit displacement is zero-extended by iced, so `[ebp-0x28]` arrives
    // as 0xffffffd8. Sign-extend it from 32 bits when it has no higher bits, so
    // frame offsets read as `- 0x28` rather than a huge positive number. A
    // 64-bit negative displacement already has all its high bits set and is
    // taken as-is.
    let raw = d.memory_displacement64();
    let disp: i64 = if raw <= 0xffff_ffff && raw & 0x8000_0000 != 0 {
        i64::from(raw as u32 as i32)
    } else {
        raw as i64
    };

    let mut inner = parts.join(" + ");
    if disp != 0 || inner.is_empty() {
        if inner.is_empty() {
            inner = format!("0x{:x}", disp as u64);
        } else if disp < 0 {
            inner.push_str(&format!(" - 0x{:x}", (-disp) as u64));
        } else {
            inner.push_str(&format!(" + 0x{disp:x}"));
        }
    }
    if deref {
        format!("*({inner})")
    } else {
        inner
    }
}

/// The value of operand `i` as an expression.
fn operand(d: &Instruction, st: &State, i: u32) -> String {
    match d.op_kind(i) {
        OpKind::Register => reg_expr(st, d.op_register(i)),
        OpKind::Memory => mem_expr(d, st, true),
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate8to32
        | OpKind::Immediate8to16 => {
            format!("0x{:x}", d.immediate(i) as u32)
        }
        OpKind::Immediate32to64 | OpKind::Immediate8to64 | OpKind::Immediate64 => {
            format!("0x{:x}", d.immediate(i))
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            format!("loc_{:x}", d.near_branch_target())
        }
        _ => "?".to_string(),
    }
}

/// Assign to operand 0 (a register or memory) and update the expression state.
fn assign(d: &Instruction, st: &mut State, rhs: String) -> String {
    match d.op0_kind() {
        OpKind::Register => {
            let r = d.op0_register().full_register();
            st.regs.insert(r, rhs.clone());
            format!("{} = {};", reg_name(d.op0_register()), rhs)
        }
        OpKind::Memory => {
            let lhs = mem_expr(d, st, true);
            format!("{lhs} = {rhs};")
        }
        _ => format!("/* {} */", raw(d)),
    }
}

/// The verbatim instruction, for anything the lifter does not model.
fn raw(d: &Instruction) -> String {
    let mut f = IntelFormatter::new();
    f.options_mut().set_uppercase_hex(false);
    f.options_mut().set_hex_prefix("0x");
    f.options_mut().set_hex_suffix("");
    let mut s = String::new();
    f.format(d, &mut s);
    s
}

fn binop(d: &Instruction, st: &mut State, op: &str) -> String {
    let a = operand(d, st, 0);
    let b = operand(d, st, 1);
    assign(d, st, format!("{a} {op} {b}"))
}

fn lift(
    d: &Instruction,
    st: &mut State,
    an: &Analysis,
    bin: &Binary,
    win64: bool,
    target_name: Option<&str>,
) -> Option<String> {
    use Mnemonic::*;
    let stmt = match d.mnemonic() {
        Nop | Endbr32 | Endbr64 => return None,
        Mov | Movzx | Movsx | Movsxd => {
            let rhs = operand(d, st, 1);
            assign(d, st, rhs)
        }
        Lea => {
            let addr = mem_expr(d, st, false);
            assign(d, st, format!("&({addr})"))
        }
        Add => binop(d, st, "+"),
        Sub => binop(d, st, "-"),
        And => binop(d, st, "&"),
        Or => binop(d, st, "|"),
        Xor => {
            // xor reg, reg is the zeroing idiom.
            if d.op0_kind() == OpKind::Register
                && d.op1_kind() == OpKind::Register
                && d.op0_register() == d.op1_register()
            {
                assign(d, st, "0".to_string())
            } else {
                binop(d, st, "^")
            }
        }
        Shl | Sal => binop(d, st, "<<"),
        Shr | Sar => binop(d, st, ">>"),
        Imul if d.op_count() >= 2 => binop(d, st, "*"),
        Inc => {
            let a = operand(d, st, 0);
            assign(d, st, format!("{a} + 1"))
        }
        Dec => {
            let a = operand(d, st, 0);
            assign(d, st, format!("{a} - 1"))
        }
        Push => {
            // Collected as a potential call argument, not printed on its own.
            st.pushed.push(operand(d, st, 0));
            return None;
        }
        Pop => {
            if d.op0_kind() == OpKind::Register {
                st.regs.remove(&d.op0_register().full_register());
            }
            return None;
        }
        Cmp => {
            st.last_cmp = Some((operand(d, st, 0), operand(d, st, 1), false));
            return None;
        }
        Test => {
            st.last_cmp = Some((operand(d, st, 0), operand(d, st, 1), true));
            return None;
        }
        Call => call(d, st, an, bin, win64, target_name),
        Ret => {
            let rv = st
                .regs
                .get(&Register::RAX)
                .cloned()
                .unwrap_or_else(|| "eax".to_string());
            format!("return {rv};")
        }
        Jmp => format!("goto {};", operand(d, st, 0)),
        _ if is_jcc(d.mnemonic()) => {
            let cond = condition(d.mnemonic(), &st.last_cmp);
            format!("if ({cond}) goto {};", operand(d, st, 0))
        }
        _ => format!("/* {} */", raw(d)),
    };
    Some(stmt)
}

fn call(
    d: &Instruction,
    st: &mut State,
    an: &Analysis,
    bin: &Binary,
    win64: bool,
    target_name: Option<&str>,
) -> String {
    // Name the callee: the resolved import/function name, or the target address.
    let name = target_name
        .map(strip_module)
        .or_else(|| {
            let t = call_target(d, an, bin)?;
            Some(an.label(t))
        })
        .unwrap_or_else(|| match d.op0_kind() {
            OpKind::Register => reg_expr(st, d.op0_register()),
            _ => "sub".to_string(),
        });

    let args = if an.bits == 32 {
        // Right-to-left pushes: reverse to get C order. Whatever was pushed
        // since the last call is the argument list.
        let mut a = st.pushed.clone();
        a.reverse();
        a
    } else {
        // 64-bit: the argument registers, up to a known arity for named calls.
        let n = arity(&name).unwrap_or(0);
        arg_registers(win64)
            .iter()
            .take(n)
            .map(|&r| reg_expr(st, r))
            .collect()
    };

    st.pushed.clear();
    clobber(st); // caller-saved registers do not survive the call
    let ret = reg_name(if an.bits == 32 {
        Register::EAX
    } else {
        Register::RAX
    });
    st.regs.remove(&Register::RAX);

    let call = format!("{name}({})", args.join(", "));
    // Only a handful of names are known to return void; showing a result
    // assignment is the safe default and reads naturally.
    format!("{ret} = {call};")
}

/// Caller-saved registers hold no known value after a call.
fn clobber(st: &mut State) {
    for r in [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ] {
        st.regs.remove(&r);
    }
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

/// Known argument counts for common APIs, so a 64-bit call shows the right
/// operands rather than a guess.
fn arity(name: &str) -> Option<usize> {
    let bare = crate::analysis::thunks::bare_name(name);
    Some(match bare {
        "strcpy" | "strcat" | "lstrcpyA" | "lstrcpyW" | "lstrcatA" | "lstrcatW" | "system"
        | "atoi" | "malloc" | "free" | "puts" | "strlen" => match bare {
            "malloc" | "free" | "atoi" | "puts" | "strlen" | "system" => 1,
            _ => 2,
        },
        "memcpy" | "memmove" | "memset" | "strncpy" | "strncat" | "snprintf" => 3,
        _ => return None,
    })
}

fn strip_module(name: &str) -> String {
    // KERNEL32!lstrcpyA -> lstrcpyA ; strcpy@plt -> strcpy
    let n = name.rsplit_once('!').map(|(_, f)| f).unwrap_or(name);
    n.strip_suffix("@plt").unwrap_or(n).to_string()
}

fn call_target(d: &Instruction, an: &Analysis, bin: &Binary) -> Option<u64> {
    let base = crate::analysis::engine::display_base(bin);
    if matches!(
        d.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    ) {
        return Some(d.near_branch_target());
    }
    if d.is_ip_rel_memory_operand() {
        let slot = d.ip_rel_memory_address();
        if an.imports.contains_key(&slot) {
            return Some(slot);
        }
    }
    let _ = base;
    None
}

fn is_jcc(m: Mnemonic) -> bool {
    let s = format!("{m:?}");
    s.starts_with('J') && m != Mnemonic::Jmp
}

/// Turn a conditional-branch mnemonic and the last comparison into a condition.
fn condition(m: Mnemonic, cmp: &Option<(String, String, bool)>) -> String {
    let (lhs, rhs, was_test) = match cmp {
        Some(c) => c.clone(),
        None => ("flags".to_string(), String::new(), false),
    };
    // After `test x, x`, jz means x == 0 and jnz means x != 0.
    if was_test {
        let op = match m {
            Mnemonic::Je => "==",
            Mnemonic::Jne => "!=",
            _ => return format!("{lhs} (from test)"),
        };
        return format!("{lhs} {op} 0");
    }
    let op = match m {
        Mnemonic::Je => "==",
        Mnemonic::Jne => "!=",
        Mnemonic::Jg | Mnemonic::Ja => ">",
        Mnemonic::Jge | Mnemonic::Jae => ">=",
        Mnemonic::Jl | Mnemonic::Jb => "<",
        Mnemonic::Jle | Mnemonic::Jbe => "<=",
        _ => return format!("{lhs} ? {rhs}"),
    };
    format!("{lhs} {op} {rhs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::engine;
    use crate::db::Db;
    use crate::model::{Arch, Section, SymKind, Symbol};

    /// Render a 32-bit function that calls `sink` after setting up pushed args.
    fn pseudo_x86(sink: &str, mut code: Vec<u8>) -> Vec<Line> {
        let va = 0x1000u64;
        let slot = 0x4000u64;
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
        let f = an.find_function(va).expect("entry recovered");
        function(&an, &bin, f)
    }

    #[test]
    fn a_call_shows_its_pushed_arguments() {
        // The CVE-2017-11882 shape: lstrcpyA(ebp-0x28, *(ebp+8)+0x1c)
        //   mov eax,[ebp+8] ; add eax,0x1c ; push eax
        //   lea eax,[ebp-0x28] ; push eax ; call [lstrcpyA]
        let code = vec![
            0x8b, 0x45, 0x08, // mov eax, [ebp+8]
            0x83, 0xc0, 0x1c, // add eax, 0x1c
            0x50, // push eax
            0x8d, 0x45, 0xd8, // lea eax, [ebp-0x28]
            0x50, // push eax
        ];
        let lines = pseudo_x86("lstrcpyA", code);
        let call = lines
            .iter()
            .find(|l| l.text.contains("lstrcpyA("))
            .expect("the call should render with a name");
        // Both arguments should be recovered expressions, not registers.
        assert!(
            call.text.contains("ebp - 0x28"),
            "destination expression: {}",
            call.text
        );
        assert!(
            call.text.contains("0x1c"),
            "source expression carries the +0x1c: {}",
            call.text
        );
    }

    #[test]
    fn an_unmodelled_instruction_is_shown_verbatim() {
        // A `cpuid` has no clean lift and must appear as raw asm, not a guess.
        let lines = pseudo_x86("puts", vec![0x0f, 0xa2]); // cpuid
        assert!(
            lines
                .iter()
                .any(|l| l.text.contains("/*") && l.text.contains("cpuid")),
            "cpuid should be a raw-asm comment"
        );
    }
}
