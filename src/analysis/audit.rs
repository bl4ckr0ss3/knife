//! The bug finder: which sink call sites look wrong, not just which exist.
//!
//! `sinks` answers "where is `memcpy` called". That still leaves a researcher
//! reading every one. `audit` reads them first: for each catalogued call it
//! recovers where the interesting argument came from and keeps only the sites
//! whose provenance matches a bug pattern. A `memcpy` whose length was just
//! computed by a subtraction, an allocation sized by a multiply, a `printf`
//! whose format string is loaded from memory rather than pointed at a
//! constant: those are where the bugs are, and those are what it prints.
//!
//! The provenance is an intra-block backward walk over x86-64 registers. It is
//! deliberately shallow and deliberately honest: it looks back only within the
//! call's own basic block, stops at the previous call (argument registers do
//! not survive one), and when it cannot see where a value came from it says
//! nothing rather than guess. That keeps the false-positive rate low enough
//! that a finding is worth a researcher's attention, which is the only metric
//! that matters for a tool like this.

use crate::analysis::engine::Analysis;
use crate::analysis::thunks::bare_name;
use crate::model::{Arch, Binary, Format};
use iced_x86::{
    Decoder, DecoderOptions, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};
use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};

/// What to inspect about a given sink, and the 1-based C argument index.
#[derive(Clone, Copy)]
enum Check {
    /// A format-string argument that should be a fixed constant, not a value
    /// loaded at runtime.
    Format(u8),
    /// An allocation size, suspicious when computed by multiplication.
    AllocSize(u8),
    /// A copy length, suspicious when computed by subtraction or multiplication.
    CopySize(u8),
    /// A copy with no length argument at all; only the reachability matters.
    Unbounded,
}

/// The auditable subset of the sink surface, with what to check on each. An
/// API may carry more than one check (`sprintf` is both a format sink and an
/// unbounded copy).
fn checks(api: &str) -> &'static [Check] {
    use Check::*;
    match api {
        // format-string sinks: the format argument, by C position
        "printf" | "vprintf" => &[Format(1)],
        "fprintf" | "vfprintf" | "syslog" | "wsprintfA" | "wsprintfW" => &[Format(2)],
        "sprintf" | "vsprintf" => &[Format(2), Unbounded],
        "snprintf" | "_snprintf" => &[Format(3)],
        // allocation size
        "malloc" => &[AllocSize(1)],
        "realloc" | "VirtualAlloc" => &[AllocSize(2)],
        "HeapAlloc" => &[AllocSize(3)],
        // sized copies: the length argument
        "memcpy" | "memmove" | "memset" | "RtlCopyMemory" | "CopyMemory" | "bcopy" | "strncpy"
        | "strncat" | "wcsncpy" => &[CopySize(3)],
        // copies with no bound
        "strcpy" | "strcat" | "gets" | "wcscpy" | "wcscat" | "lstrcpyA" | "lstrcpyW"
        | "lstrcatA" | "lstrcatW" | "StrCpyA" | "StrCpyW" => &[Unbounded],
        _ => &[],
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Address of the calling instruction.
    pub addr: u64,
    pub func: Option<String>,
    pub api: String,
    /// Kebab-case pattern id, stable for scripting.
    pub pattern: &'static str,
    /// 3 = looks exploitable, 2 = worth a close look, 1 = context worth knowing.
    pub severity: u8,
    pub detail: String,
    /// The call sits in a function reachable from an entry point or export.
    pub reachable: bool,
}

/// What the backward walk concluded about where a register's value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// A fixed address: `lea reg, [rip+k]` or `mov reg, imm`. Not attacker
    /// controlled, so a format pointer that is one of these is safe.
    Fixed,
    /// Loaded from memory or copied from another register: a runtime value.
    Dynamic,
    /// Produced by a multiply or a left shift.
    Multiply,
    /// Produced by a subtraction.
    Subtract,
    /// A small constant immediate (a length known at compile time).
    Constant,
    /// No defining instruction was found in the block before the call.
    Unknown,
}

pub fn run(an: &Analysis, bin: &Binary, bytes: &[u8]) -> Vec<Finding> {
    // The provenance walk is x86-only; other architectures get no findings
    // rather than wrong ones. The caller tells the user why.
    if !matches!(an.arch, Arch::X86 | Arch::X86_64) {
        return Vec::new();
    }
    let win64 = bin.format == Format::Pe && an.bits == 64;
    let reachable = reachable_functions(an, bin);

    let mut out = Vec::new();
    for f in &an.functions {
        let from_entry = reachable.contains(&f.addr);
        for block in &f.blocks {
            for (i, ins) in block.insns.iter().enumerate() {
                let Some(target) = ins.target else { continue };
                // Resolve the call target to a bare API name.
                let Some(full) = an.imports.get(&target).or_else(|| an.names.get(&target)) else {
                    continue;
                };
                let api = bare_name(full);
                let cs = checks(api);
                if cs.is_empty() {
                    continue;
                }
                for check in cs {
                    if let Some(mut fnd) =
                        classify(*check, api, an, bin, bytes, block, i, win64, from_entry)
                    {
                        fnd.func = Some(f.name.clone());
                        out.push(fnd);
                    }
                }
            }
        }
    }

    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.reachable.cmp(&a.reachable))
            .then(a.addr.cmp(&b.addr))
    });
    out
}

#[allow(clippy::too_many_arguments)]
fn classify(
    check: Check,
    api: &str,
    an: &Analysis,
    bin: &Binary,
    bytes: &[u8],
    block: &crate::analysis::engine::BasicBlock,
    call_idx: usize,
    win64: bool,
    reachable: bool,
) -> Option<Finding> {
    let addr = block.insns[call_idx].addr + an.display_base;
    let mk = |pattern, severity, detail: String| Finding {
        addr,
        func: None,
        api: api.to_string(),
        pattern,
        severity,
        detail,
        reachable,
    };

    match check {
        Check::Unbounded => {
            // No argument to inspect; the finding is the call plus its reach.
            let sev = if reachable { 3 } else { 2 };
            let detail = if reachable {
                "unbounded copy reachable from an entry point or export".to_string()
            } else {
                "unbounded copy; no length argument bounds the write".to_string()
            };
            Some(mk("unbounded-copy", sev, detail))
        }
        Check::Format(arg) => {
            // A format pointer that is a fixed constant is the normal, safe
            // case; a runtime pointer is the format-string bug. Anything we
            // could not resolve is left alone rather than guessed at.
            match provenance(an, bin, bytes, block, call_idx, arg, win64).origin {
                Origin::Dynamic => Some(mk(
                    "format-string",
                    3,
                    "format argument is loaded at runtime, not a constant string".to_string(),
                )),
                _ => None,
            }
        }
        // A size that is clamped or masked before the call cannot actually reach
        // an extreme, so the finding is kept but ranked well below the raw ones:
        // still worth a glance, no longer worth an afternoon.
        Check::AllocSize(arg) => {
            let p = provenance(an, bin, bytes, block, call_idx, arg, win64);
            match p.origin {
                Origin::Multiply => Some(sized(
                    &mk,
                    "alloc-overflow",
                    3,
                    "allocation size computed by multiplication (integer overflow?)",
                    p.bounded,
                )),
                Origin::Subtract => Some(sized(
                    &mk,
                    "alloc-underflow",
                    2,
                    "allocation size computed by subtraction",
                    p.bounded,
                )),
                _ => None,
            }
        }
        Check::CopySize(arg) => {
            let p = provenance(an, bin, bytes, block, call_idx, arg, win64);
            match p.origin {
                Origin::Subtract => Some(sized(
                    &mk,
                    "copy-underflow",
                    3,
                    "copy length computed by subtraction (integer underflow to a huge size?)",
                    p.bounded,
                )),
                Origin::Multiply => Some(sized(
                    &mk,
                    "copy-overflow",
                    2,
                    "copy length computed by multiplication (integer overflow?)",
                    p.bounded,
                )),
                _ => None,
            }
        }
    }
}

/// Build a size-argument finding, downgrading it a band and annotating it when
/// the value was clamped or masked before the call.
fn sized(
    mk: &dyn Fn(&'static str, u8, String) -> Finding,
    pattern: &'static str,
    severity: u8,
    detail: &str,
    bounded: bool,
) -> Finding {
    if bounded {
        // A clamped or masked size is likely safe, so it sinks to the bottom
        // band rather than merely one step down.
        mk(
            pattern,
            1,
            format!("{detail}; but clamped or masked before the call, likely safe"),
        )
    } else {
        mk(pattern, severity, detail.to_string())
    }
}

/// Which 64-bit register carries C argument `n` (1-based) under the ABI.
fn arg_register(n: u8, win64: bool) -> Option<Register> {
    let table: &[Register] = if win64 {
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
    table.get((n as usize).checked_sub(1)?).copied()
}

/// What the backward walk found about an argument: where its value came from,
/// and whether it was bounded before the call.
struct Prov {
    origin: Origin,
    /// A clamp (`cmp` + `cmov`) or a mask (`and reg, imm`) was applied to the
    /// value between its computation and the call, so a raw subtraction or
    /// multiply cannot actually reach an extreme.
    bounded: bool,
}

/// Walk backward through the block from the call to find where the argument
/// register was last written, classify it, and note any clamp on the way.
fn provenance(
    an: &Analysis,
    bin: &Binary,
    bytes: &[u8],
    block: &crate::analysis::engine::BasicBlock,
    call_idx: usize,
    arg: u8,
    win64: bool,
) -> Prov {
    let Some(target) = arg_register(arg, win64) else {
        return Prov {
            origin: Origin::Unknown,
            bounded: false,
        };
    };
    // The register we are currently tracing. A plain register-to-register move
    // retargets it to the source, so a value that was computed in one register
    // and moved into the argument register is followed to its real origin.
    let mut want = target.full_register();
    let mut bounded = false;

    let mut info = InstructionInfoFactory::new();
    for j in (0..call_idx).rev() {
        let ins = &block.insns[j];
        let Some(d) = decode_one(&ins.bytes, ins.addr, an.bits) else {
            continue;
        };
        // Argument registers do not survive an intervening call, so a value set
        // before one is not the value passed here.
        if matches!(d.mnemonic(), Mnemonic::Call) {
            return Prov {
                origin: Origin::Unknown,
                bounded,
            };
        }

        // A conditional move into the tracked register is the min/max clamp
        // idiom (`cmp size, limit; cmova size, limit`). It writes the register
        // only conditionally, so the backward walk would otherwise step past it
        // to the raw arithmetic and call a bounded value dangerous. Record the
        // clamp and keep following the kept value.
        if is_cmov(&d) && writes_reg(&mut info, &d, want) {
            bounded = true;
            continue;
        }

        let writes = writes_reg(&mut info, &d, want);
        if !writes {
            continue;
        }
        // A mask bounds the value to the immediate, which is the other way a
        // subtraction or product is made safe.
        if d.mnemonic() == Mnemonic::And && d.op1_kind() != OpKind::Register {
            bounded = true;
        }
        // Follow a copy: `mov edi, eax` means the value's real origin is
        // whatever last wrote eax, so keep walking with that register.
        if d.mnemonic() == Mnemonic::Mov
            && d.op0_kind() == OpKind::Register
            && d.op1_kind() == OpKind::Register
        {
            want = d.op1_register().full_register();
            continue;
        }
        return Prov {
            origin: origin_of(&d, bin, an, bytes),
            bounded,
        };
    }
    Prov {
        origin: Origin::Unknown,
        bounded,
    }
}

/// Does this instruction write (or conditionally write) the given 64-bit reg?
fn writes_reg(info: &mut InstructionInfoFactory, d: &Instruction, want: Register) -> bool {
    info.info(d)
        .used_registers()
        .iter()
        .filter(|u| {
            matches!(
                u.access(),
                OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite
            )
        })
        .any(|u| u.register().is_gpr() && u.register().full_register() == want)
}

/// Every conditional-move variant, without listing all sixteen: their debug
/// names all begin with `Cmov`.
fn is_cmov(d: &Instruction) -> bool {
    format!("{:?}", d.mnemonic()).starts_with("Cmov")
}

/// Classify the instruction that defined an argument register.
fn origin_of(d: &Instruction, bin: &Binary, an: &Analysis, bytes: &[u8]) -> Origin {
    match d.mnemonic() {
        Mnemonic::Imul | Mnemonic::Mul => Origin::Multiply,
        // A left shift is a multiply by a power of two; on a size it overflows
        // the same way.
        Mnemonic::Shl | Mnemonic::Sal => Origin::Multiply,
        Mnemonic::Sub | Mnemonic::Sbb => Origin::Subtract,
        // `lea reg, [base + index*scale]` with a real index is a multiply; a
        // plain `lea reg, [rip+k]` is a fixed address.
        Mnemonic::Lea => {
            if d.memory_index() != Register::None {
                Origin::Multiply
            } else {
                Origin::Fixed
            }
        }
        Mnemonic::Mov => classify_mov(d, bin, an, bytes),
        Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => Origin::Dynamic,
        Mnemonic::Xor => {
            // xor reg, reg is the idiom for zero.
            if d.op0_register() == d.op1_register() {
                Origin::Constant
            } else {
                Origin::Dynamic
            }
        }
        _ => Origin::Dynamic,
    }
}

fn classify_mov(d: &Instruction, bin: &Binary, an: &Analysis, bytes: &[u8]) -> Origin {
    match d.op1_kind() {
        // mov reg, imm: a compile-time constant. A pointer-sized immediate that
        // lands on a mapped string is a fixed format pointer; otherwise it is a
        // constant length.
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate32to64
        | OpKind::Immediate64 => {
            let imm = d.immediate(1);
            if points_at_string(bin, an, bytes, imm) {
                Origin::Fixed
            } else {
                Origin::Constant
            }
        }
        // mov reg, [mem]: a runtime load.
        OpKind::Memory => Origin::Dynamic,
        // mov reg, reg: value came from another register (often a call return).
        OpKind::Register => Origin::Dynamic,
        _ => Origin::Dynamic,
    }
}

/// Does this address land within a string literal in a mapped section? Used to
/// tell a fixed format-string pointer from a dangerous runtime one.
fn points_at_string(bin: &Binary, an: &Analysis, bytes: &[u8], va: u64) -> bool {
    let base = an.display_base;
    let Some(off) = crate::analysis::engine::va_to_off(bin, base, va) else {
        return false;
    };
    // A printable run of a few bytes at the target is a string constant.
    bytes
        .get(off..off + 4)
        .is_some_and(|w| w.iter().all(|&b| (0x20..0x7f).contains(&b)))
}

/// Decode a single instruction from an engine block's stored bytes, so the
/// audit can read operands the block model does not keep.
fn decode_one(raw: &[u8], ip: u64, bits: u32) -> Option<Instruction> {
    if raw.is_empty() {
        return None;
    }
    let mut dec = Decoder::with_ip(bits, raw, ip, DecoderOptions::NONE);
    if !dec.can_decode() {
        return None;
    }
    let insn = dec.decode();
    (!insn.is_invalid()).then_some(insn)
}

/// Functions reachable from the entry point or an export, by forward walk over
/// the recovered call graph. A sink inside one of these is attacker-reachable.
fn reachable_functions(an: &Analysis, bin: &Binary) -> BTreeSet<u64> {
    let base = crate::analysis::engine::display_base(bin);
    let is_func: BTreeSet<u64> = an.functions.iter().map(|f| f.addr).collect();

    let mut roots: Vec<u64> = bin
        .symbols
        .iter()
        .filter(|s| s.kind == crate::model::SymKind::Export)
        .map(|s| s.addr + base)
        .filter(|a| is_func.contains(a))
        .collect();
    let entry = bin.entry + base;
    if is_func.contains(&entry) {
        roots.push(entry);
    }

    let mut seen: BTreeSet<u64> = roots.iter().copied().collect();
    let mut queue: VecDeque<u64> = roots.into_iter().collect();
    while let Some(a) = queue.pop_front() {
        let Some(f) = an.find_function(a) else {
            continue;
        };
        for &callee in &f.calls {
            if is_func.contains(&callee) && seen.insert(callee) {
                queue.push_back(callee);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::engine;
    use crate::db::Db;
    use crate::model::{Section, SymKind, Symbol};

    /// Assemble a single function: a run of x86-64 bytes at `va` ending in the
    /// caller's `ret`, plus an imported sink at `slot` that the code calls via
    /// `call [rip]`. Returns the analysis so a test can audit it.
    struct Harness {
        bin: Binary,
        bytes: Vec<u8>,
    }

    impl Harness {
        /// `code` is placed at 0x1000; `sink` is imported at slot 0x4000 and is
        /// the target of the final `call qword [rip+disp]` the caller appends.
        fn new(sink: &str, mut code: Vec<u8>) -> Harness {
            let va = 0x1000u64;
            let slot = 0x4000u64;
            // call qword ptr [rip+disp] -> slot. Instruction is 6 bytes.
            let call_at = va + code.len() as u64;
            let disp = (slot as i64 - (call_at as i64 + 6)) as i32;
            code.push(0xff);
            code.push(0x15);
            code.extend_from_slice(&disp.to_le_bytes());
            code.push(0xc3); // ret

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
            bin.symbols = vec![Symbol {
                addr: slot,
                name: sink.into(),
                kind: SymKind::Import,
            }];
            let mut bytes = vec![0u8; va as usize];
            bytes.extend_from_slice(&code);
            Harness { bin, bytes }
        }

        fn findings(&self) -> Vec<Finding> {
            let an = engine::analyze(&self.bin, &self.bytes, 10_000, &Db::default());
            run(&an, &self.bin, &self.bytes)
        }
    }

    #[test]
    fn memcpy_length_from_subtraction_is_flagged() {
        // mov rdi, rsi ; mov edx, ecx ; sub edx, eax ; call memcpy
        // The length (rdx, SysV arg3) is a subtraction: underflow candidate.
        let code = vec![
            0x48, 0x89, 0xf7, // mov rdi, rsi
            0x89, 0xca, // mov edx, ecx
            0x29, 0xc2, // sub edx, eax
        ];
        let f = Harness::new("memcpy", code).findings();
        let hit = f
            .iter()
            .find(|x| x.pattern == "copy-underflow")
            .expect("expected copy-underflow");
        assert_eq!(hit.severity, 3, "an unclamped subtraction is high severity");
    }

    #[test]
    fn a_clamped_subtraction_is_downgraded_not_dropped() {
        // sub edx, eax ; cmp edx, ecx ; cmova edx, ecx ; call memcpy
        // The length (rdx, SysV arg3) is a subtraction, but the cmov clamps it,
        // so it is the safe min()/max() idiom, not an underflow. The finding
        // should survive but drop below the raw ones.
        let code = vec![
            0x29, 0xc2, // sub edx, eax
            0x39, 0xca, // cmp edx, ecx
            0x0f, 0x47, 0xd1, // cmova edx, ecx
        ];
        let f = Harness::new("memcpy", code).findings();
        let hit = f
            .iter()
            .find(|x| x.pattern == "copy-underflow")
            .expect("still reported");
        assert_eq!(hit.severity, 1, "a clamped subtraction is downgraded");
        assert!(hit.detail.contains("clamped or masked"));
    }

    #[test]
    fn a_clamp_through_a_move_hop_is_detected() {
        // The exact shape seen in 7z.dll: the length is computed in one 64-bit
        // register, clamped there with a cmov, then moved into the argument
        // register. The walk must follow the move and still see the clamp.
        //   sub r12, rax ; cmp r12, rcx ; cmova r12, rcx ; mov rdx, r12 ; call
        let code = vec![
            0x49, 0x29, 0xc4, // sub r12, rax
            0x49, 0x39, 0xcc, // cmp r12, rcx
            0x4c, 0x0f, 0x47, 0xe1, // cmova r12, rcx
            0x4c, 0x89, 0xe2, // mov rdx, r12   (rdx = SysV arg3)
        ];
        let f = Harness::new("memcpy", code).findings();
        let hit = f
            .iter()
            .find(|x| x.pattern == "copy-underflow")
            .expect("still reported");
        assert_eq!(hit.severity, 1, "the clamp is seen through the move hop");
    }

    #[test]
    fn malloc_size_from_multiply_is_flagged() {
        // mov eax, edi ; imul eax, esi ; mov edi, eax ; call malloc
        // The size (rdi, SysV arg1) traces to an imul: overflow candidate.
        let code = vec![
            0x89, 0xf8, // mov eax, edi
            0x0f, 0xaf, 0xc6, // imul eax, esi
            0x89, 0xc7, // mov edi, eax
        ];
        let f = Harness::new("malloc", code).findings();
        assert!(
            f.iter().any(|x| x.pattern == "alloc-overflow"),
            "expected alloc-overflow, got {:?}",
            f.iter().map(|x| x.pattern).collect::<Vec<_>>()
        );
    }

    #[test]
    fn memcpy_with_a_constant_length_is_not_flagged() {
        // mov edx, 0x10 ; call memcpy — a fixed length is not a bug.
        let code = vec![0xba, 0x10, 0x00, 0x00, 0x00]; // mov edx, 16
        let f = Harness::new("memcpy", code).findings();
        assert!(
            !f.iter().any(|x| x.pattern.starts_with("copy-")),
            "a constant length must not be flagged: {:?}",
            f.iter().map(|x| x.pattern).collect::<Vec<_>>()
        );
    }

    #[test]
    fn printf_with_a_runtime_format_is_flagged() {
        // mov rdi, [rsi] ; call printf — format loaded from memory.
        let code = vec![0x48, 0x8b, 0x3e]; // mov rdi, [rsi]
        let f = Harness::new("printf", code).findings();
        assert!(
            f.iter().any(|x| x.pattern == "format-string"),
            "expected format-string, got {:?}",
            f.iter().map(|x| x.pattern).collect::<Vec<_>>()
        );
    }

    #[test]
    fn printf_with_a_fixed_format_pointer_is_not_flagged() {
        // lea rdi, [rip+k] ; call printf — a constant format string is fine.
        let code = vec![0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00]; // lea rdi,[rip+0x10]
        let f = Harness::new("printf", code).findings();
        assert!(
            !f.iter().any(|x| x.pattern == "format-string"),
            "a fixed format pointer must not be flagged: {:?}",
            f.iter().map(|x| x.pattern).collect::<Vec<_>>()
        );
    }

    #[test]
    fn strcpy_reachable_from_entry_is_high_severity() {
        // The harness places the code at the entry point, so the call is
        // reachable; an unbounded copy there is the worst case.
        let f = Harness::new("strcpy", Vec::new()).findings();
        let u = f
            .iter()
            .find(|x| x.pattern == "unbounded-copy")
            .expect("unbounded-copy expected");
        assert!(u.reachable);
        assert_eq!(u.severity, 3);
    }

    #[test]
    fn a_value_set_before_an_intervening_call_is_not_attributed() {
        // mov edx, eax (a subtraction would flag, but here it is a plain move
        // BEFORE a call) ; call something ; call memcpy — rdx does not survive
        // the first call, so the sub is not the memcpy length.
        // Represented minimally: sub edx,eax ; call [rip] (other) ; then the
        // harness appends call memcpy. The sub precedes an intervening call.
        // other import at a different slot:
        let va = 0x1000u64;
        let other = 0x5000u64;
        let mut code = vec![0x29, 0xc2]; // sub edx, eax
        let call_at = va + code.len() as u64;
        let disp = (other as i64 - (call_at as i64 + 6)) as i32;
        code.push(0xff);
        code.push(0x15);
        code.extend_from_slice(&disp.to_le_bytes()); // call [rip] -> other
        let mut h = Harness::new("memcpy", code);
        h.bin.symbols.push(Symbol {
            addr: other,
            name: "getpid".into(),
            kind: SymKind::Import,
        });
        let f = h.findings();
        assert!(
            !f.iter().any(|x| x.pattern == "copy-underflow"),
            "a value set before an intervening call must not be attributed"
        );
    }
}
