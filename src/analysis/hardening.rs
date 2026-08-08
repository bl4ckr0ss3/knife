//! Exploit-mitigation audit: what defences the target was built with, and what
//! their absence buys an attacker.
//!
//! This is the first question in vulnerability research and the last one in
//! triage, so it gets its own command. The rule throughout is that a header bit
//! is a claim, not a fact: ASLR without relocations does not move anything, a
//! CFG flag without a guard function table checks nothing, and SafeSEH is only
//! real if the handler table has entries. Where the two disagree, the audit
//! reports what the binary can actually do.

use crate::model::{Binary, Format, HardeningFacts};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum State {
    /// Present and backed by real data.
    On,
    /// Present but weakened, or covering only part of what it names.
    Partial,
    /// Absent, and its absence is exploitable.
    Off,
    /// Does not apply to this format/architecture; reported so its absence is
    /// never misread as a missing defence.
    NotApplicable,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            State::On => "enabled",
            State::Partial => "partial",
            State::Off => "disabled",
            State::NotApplicable => "n/a",
        }
    }
    /// Maps onto the shared `[+]` / `[=]` / `[-]` marker vocabulary.
    pub fn kind(self) -> &'static str {
        match self {
            State::On => "info",
            State::Partial => "warn",
            State::Off => "bad",
            State::NotApplicable => "na",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub name: &'static str,
    pub state: State,
    /// What the container actually says, with the numbers that prove it.
    pub detail: String,
    /// What this means for someone attacking the binary.
    pub impact: &'static str,
    /// Contribution to the exposure score when `Off` (halved when `Partial`).
    pub weight: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Exposure {
    Hardened,
    Moderate,
    Weak,
    Bare,
}

impl Exposure {
    pub fn label(self) -> &'static str {
        match self {
            Exposure::Hardened => "HARDENED",
            Exposure::Moderate => "MODERATE",
            Exposure::Weak => "WEAK",
            Exposure::Bare => "BARE",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub score: u32,
    pub exposure: Exposure,
    /// Missing / total, counting only mitigations that apply to this target.
    pub missing: usize,
    pub applicable: usize,
}

// ── PE DLL characteristics ──
const DYNAMIC_BASE: u16 = 0x0040;
const HIGH_ENTROPY_VA: u16 = 0x0020;
const FORCE_INTEGRITY: u16 = 0x0080;
const NX_COMPAT: u16 = 0x0100;
const NO_ISOLATION: u16 = 0x0200;
const NO_SEH: u16 = 0x0400;
const APPCONTAINER: u16 = 0x1000;
const GUARD_CF: u16 = 0x4000;

// ── PE load-config guard flags ──
const GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
const GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
const GUARD_SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
const GUARD_RF_INSTRUMENTED: u32 = 0x0002_0000;
const GUARD_RETPOLINE_PRESENT: u32 = 0x0010_0000;
const GUARD_EH_CONTINUATION_TABLE: u32 = 0x0040_0000;

// ── Mach-O header flags ──
const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

pub fn run(bin: &Binary) -> Report {
    let h = &bin.hardening;
    let findings = match bin.format {
        Format::Pe => pe_findings(bin, h),
        Format::Elf => elf_findings(bin, h),
        Format::MachO => macho_findings(bin, h),
        _ => Vec::new(),
    };

    let score: u32 = findings
        .iter()
        .map(|f| match f.state {
            State::Off => f.weight,
            State::Partial => f.weight / 2,
            _ => 0,
        })
        .sum();
    let applicable = findings
        .iter()
        .filter(|f| f.state != State::NotApplicable)
        .count();
    let missing = findings
        .iter()
        .filter(|f| matches!(f.state, State::Off | State::Partial))
        .count();

    // Thresholds are tuned so that a stock hardened toolchain build lands in
    // HARDENED and a binary missing both ASLR and a canary cannot.
    let exposure = match score {
        0..=2 => Exposure::Hardened,
        3..=6 => Exposure::Moderate,
        7..=11 => Exposure::Weak,
        _ => Exposure::Bare,
    };

    Report {
        findings,
        score,
        exposure,
        missing,
        applicable,
    }
}

fn f(
    name: &'static str,
    state: State,
    detail: impl Into<String>,
    impact: &'static str,
    weight: u32,
) -> Finding {
    Finding {
        name,
        state,
        detail: detail.into(),
        impact,
        weight,
    }
}

fn pe_findings(bin: &Binary, h: &HardeningFacts) -> Vec<Finding> {
    let dc = h.dll_characteristics.unwrap_or(0);
    let lc = h.load_config.clone().unwrap_or_default();
    let mut out = Vec::new();

    // ASLR. The DYNAMIC_BASE bit is a request; without a relocation table the
    // loader has nothing to rewrite, so the image lands at its preferred base
    // regardless. Report the effective outcome.
    let has_reloc = bin.sections.iter().any(|s| s.name.starts_with(".reloc"));
    out.push(match (dc & DYNAMIC_BASE != 0, has_reloc) {
        (true, true) => f(
            "ASLR",
            State::On,
            "DYNAMIC_BASE set, .reloc present",
            "image base is randomised per boot",
            0,
        ),
        (true, false) => f(
            "ASLR",
            State::Partial,
            "DYNAMIC_BASE set but no .reloc section",
            "relocations stripped, so the image still loads at its preferred base",
            4,
        ),
        (false, _) => f(
            "ASLR",
            State::Off,
            format!("DYNAMIC_BASE clear, preferred base 0x{:x}", bin.image_base),
            "every image address is known ahead of time, gadgets included",
            4,
        ),
    });

    // High-entropy ASLR only means anything in a 64-bit address space.
    out.push(if bin.bits != 64 {
        f(
            "high-entropy ASLR",
            State::NotApplicable,
            "32-bit image",
            "only 64-bit images can use the wide address space",
            0,
        )
    } else if dc & HIGH_ENTROPY_VA != 0 {
        f(
            "high-entropy ASLR",
            State::On,
            "HIGH_ENTROPY_VA set",
            "full 64-bit randomisation, brute force is not viable",
            0,
        )
    } else {
        f(
            "high-entropy ASLR",
            State::Off,
            "HIGH_ENTROPY_VA clear",
            "randomisation is limited to the low 32 bits and can be brute forced",
            2,
        )
    });

    out.push(if dc & NX_COMPAT != 0 {
        f(
            "DEP / NX",
            State::On,
            "NX_COMPAT set",
            "data pages are non-executable, so shellcode needs ROP first",
            0,
        )
    } else {
        f(
            "DEP / NX",
            State::Off,
            "NX_COMPAT clear",
            "the stack and heap stay executable, so injected code runs directly",
            4,
        )
    });

    // Stack cookies. The load config holds the pointer the prologue reads; a
    // zero pointer means no /GS-instrumented function in the image.
    let cookie_unused = lc.guard_flags & GUARD_SECURITY_COOKIE_UNUSED != 0;
    out.push(if lc.security_cookie != 0 && !cookie_unused {
        f(
            "stack cookies (/GS)",
            State::On,
            format!("__security_cookie at 0x{:x}", lc.security_cookie),
            "stack overflows are caught before the return address is used",
            0,
        )
    } else if cookie_unused {
        f(
            "stack cookies (/GS)",
            State::Off,
            "load config declares the security cookie unused",
            "linear stack overflows reach the saved return address unchecked",
            3,
        )
    } else {
        f(
            "stack cookies (/GS)",
            State::Off,
            "no __security_cookie in the load config",
            "linear stack overflows reach the saved return address unchecked",
            3,
        )
    });

    // Control Flow Guard. The header bit and the guard function table have to
    // agree: a bit with an empty table protects nothing.
    let cf_bit = dc & GUARD_CF != 0;
    let cf_table = lc.guard_flags & GUARD_CF_FUNCTION_TABLE_PRESENT != 0 && lc.guard_cf_count > 0;
    let cf_instr = lc.guard_flags & GUARD_CF_INSTRUMENTED != 0;
    out.push(match (cf_bit, cf_table && cf_instr) {
        (true, true) => f(
            "CFG",
            State::On,
            format!("{} guarded call targets", lc.guard_cf_count),
            "indirect calls are checked, so function-pointer overwrites are constrained",
            0,
        ),
        (true, false) => f(
            "CFG",
            State::Partial,
            "GUARD_CF set but the guard function table is empty",
            "the flag is advertised without instrumentation behind it",
            2,
        ),
        (false, _) => f(
            "CFG",
            State::Off,
            "GUARD_CF clear",
            "indirect calls are unchecked, so any writable function pointer is a target",
            3,
        ),
    });

    // SEH is only an exploitation route on 32-bit x86, where handlers live on
    // the stack. 64-bit uses table-based unwinding and cannot be hijacked the
    // same way, so it is reported as not applicable rather than missing.
    out.push(if bin.bits == 64 {
        f(
            "SafeSEH",
            State::NotApplicable,
            "64-bit uses table-based exception handling",
            "SEH overwrite does not apply to this architecture",
            0,
        )
    } else if dc & NO_SEH != 0 {
        f(
            "SafeSEH",
            State::On,
            "NO_SEH set",
            "the image uses no SEH at all, so there is no handler chain to overwrite",
            0,
        )
    } else if lc.seh_table != 0 && lc.seh_count > 0 {
        f(
            "SafeSEH",
            State::On,
            format!("{} registered handlers", lc.seh_count),
            "only registered handlers run, so SEH overwrite is blocked",
            0,
        )
    } else {
        f(
            "SafeSEH",
            State::Off,
            "no SEH handler table",
            "an overflow past the handler chain redirects execution on the next fault",
            3,
        )
    });

    // Return Flow Guard and EH continuation metadata are newer and rarely on;
    // report them without penalty so they read as intelligence, not as debt.
    if lc.guard_flags & GUARD_RF_INSTRUMENTED != 0 {
        out.push(f(
            "RFG",
            State::On,
            "return flow guard instrumented",
            "return addresses are validated",
            0,
        ));
    }
    if lc.guard_flags & GUARD_EH_CONTINUATION_TABLE != 0 {
        out.push(f(
            "EH continuation",
            State::On,
            "EH continuation table present",
            "exception continuation targets are constrained",
            0,
        ));
    }
    if lc.guard_flags & GUARD_RETPOLINE_PRESENT != 0 {
        out.push(f(
            "retpoline",
            State::On,
            "retpoline present",
            "indirect branches are speculation-hardened",
            0,
        ));
    }

    out.push(if bin.has_signature {
        f(
            "Authenticode",
            State::On,
            "certificate table present",
            "the file is signed, though knife does not verify the chain",
            0,
        )
    } else {
        f(
            "Authenticode",
            State::Off,
            "no certificate table",
            "unsigned, so tampering leaves no signature to break",
            1,
        )
    });

    if dc & FORCE_INTEGRITY != 0 {
        out.push(f(
            "force integrity",
            State::On,
            "FORCE_INTEGRITY set",
            "the loader refuses to map this image unsigned",
            0,
        ));
    }
    if dc & APPCONTAINER != 0 {
        out.push(f(
            "AppContainer",
            State::On,
            "APPCONTAINER set",
            "runs sandboxed with a restricted token",
            0,
        ));
    }
    if dc & NO_ISOLATION != 0 {
        out.push(f(
            "isolation",
            State::Partial,
            "NO_ISOLATION set",
            "side-by-side manifest isolation is disabled",
            1,
        ));
    }

    // A writable and executable section defeats DEP inside the image itself.
    if let Some(s) = bin.sections.iter().find(|s| s.is_wx()) {
        out.push(f(
            "W^X",
            State::Off,
            format!("section {} is writable and executable", s.name),
            "a writable code page is a ready-made place to stage shellcode",
            3,
        ));
    }

    out
}

fn elf_findings(bin: &Binary, h: &HardeningFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    // PT_GNU_STACK absent is not the same as present-and-writable: the loader
    // falls back to an executable stack, which is the worse of the two.
    out.push(match h.gnu_stack_exec {
        Some(false) => f(
            "NX",
            State::On,
            "PT_GNU_STACK is RW",
            "the stack is non-executable, so shellcode needs ROP first",
            0,
        ),
        Some(true) => f(
            "NX",
            State::Off,
            "PT_GNU_STACK is RWX",
            "the stack is executable, so injected code runs directly",
            4,
        ),
        None => f(
            "NX",
            State::Off,
            "no PT_GNU_STACK header",
            "the loader defaults to an executable stack when the header is absent",
            4,
        ),
    });

    // ET_DYN is the position-independent case; `is_lib` is what separates a PIE
    // program from a shared object, and shared objects are position-independent
    // by construction, so PIE is only a meaningful question for the executable.
    const ET_DYN: u16 = 3;
    let pie = h.elf_type == ET_DYN;
    out.push(if bin.is_lib {
        f(
            "PIE",
            State::NotApplicable,
            "shared object, position-independent by construction",
            "libraries always load at a randomised base",
            0,
        )
    } else if pie {
        f(
            "PIE",
            State::On,
            "ET_DYN executable with an interpreter",
            "the image base is randomised, so leaked pointers are needed first",
            0,
        )
    } else {
        f(
            "PIE",
            State::Off,
            "ET_EXEC, fixed load address",
            "every code and data address is static, gadgets included",
            4,
        )
    });

    out.push(match (h.gnu_relro, h.bind_now) {
        (true, true) => f(
            "RELRO",
            State::On,
            "PT_GNU_RELRO with BIND_NOW",
            "the GOT is read-only after startup, so GOT overwrite is closed",
            0,
        ),
        (true, false) => f(
            "RELRO",
            State::Partial,
            "PT_GNU_RELRO without BIND_NOW",
            "the GOT stays writable for lazy binding, so GOT overwrite still works",
            3,
        ),
        (false, _) => f(
            "RELRO",
            State::Off,
            "no PT_GNU_RELRO",
            "the GOT and .init_array are writable for the process lifetime",
            4,
        ),
    });

    out.push(if h.stack_chk {
        f(
            "stack canary",
            State::On,
            "__stack_chk_fail referenced",
            "stack overflows are caught before the return address is used",
            0,
        )
    } else {
        f(
            "stack canary",
            State::Off,
            "no __stack_chk_fail reference",
            "linear stack overflows reach the saved return address unchecked",
            3,
        )
    });

    out.push(if h.fortify_syms > 0 {
        f(
            "FORTIFY_SOURCE",
            State::On,
            format!("{} fortified libc wrappers", h.fortify_syms),
            "buffer sizes are checked where the compiler could prove them",
            0,
        )
    } else {
        f(
            "FORTIFY_SOURCE",
            State::Off,
            "no _chk wrappers",
            "unchecked memcpy/sprintf even where the destination size was known",
            2,
        )
    });

    if h.textrel {
        out.push(f(
            "text relocations",
            State::Off,
            "DT_TEXTREL present",
            "code pages must be writable at load, which weakens W^X",
            3,
        ));
    }

    // RPATH/RUNPATH bakes a search path into the binary. `$ORIGIN`-free
    // writable paths are a classic local privilege-escalation route.
    if !bin.rpaths.is_empty() {
        out.push(f(
            "RPATH / RUNPATH",
            State::Off,
            bin.rpaths.join(", "),
            "a baked-in library search path is a hijack route if any entry is writable",
            2,
        ));
    }

    if let Some(s) = bin.sections.iter().find(|s| s.is_wx()) {
        out.push(f(
            "W^X",
            State::Off,
            format!("section {} is writable and executable", s.name),
            "a writable code page is a ready-made place to stage shellcode",
            3,
        ));
    }

    out
}

fn macho_findings(bin: &Binary, h: &HardeningFacts) -> Vec<Finding> {
    let flags = h.macho_flags.unwrap_or(0);
    let mut out = Vec::new();

    out.push(if flags & MH_PIE != 0 {
        f(
            "PIE",
            State::On,
            "MH_PIE set",
            "the image base is randomised, so leaked pointers are needed first",
            0,
        )
    } else if bin.is_lib {
        f(
            "PIE",
            State::NotApplicable,
            "dylib, position-independent by construction",
            "libraries always load at a randomised base",
            0,
        )
    } else {
        f(
            "PIE",
            State::Off,
            "MH_PIE clear",
            "every code and data address is static, gadgets included",
            4,
        )
    });

    out.push(if flags & MH_ALLOW_STACK_EXECUTION != 0 {
        f(
            "NX stack",
            State::Off,
            "MH_ALLOW_STACK_EXECUTION set",
            "the stack is executable, so injected code runs directly",
            4,
        )
    } else {
        f(
            "NX stack",
            State::On,
            "stack execution not requested",
            "the stack is non-executable, so shellcode needs ROP first",
            0,
        )
    });

    if flags & MH_NO_HEAP_EXECUTION != 0 {
        out.push(f(
            "NX heap",
            State::On,
            "MH_NO_HEAP_EXECUTION set",
            "heap pages are explicitly non-executable",
            0,
        ));
    }

    out.push(if h.stack_chk {
        f(
            "stack canary",
            State::On,
            "___stack_chk_fail imported",
            "stack overflows are caught before the return address is used",
            0,
        )
    } else {
        f(
            "stack canary",
            State::Off,
            "no ___stack_chk_fail import",
            "linear stack overflows reach the saved return address unchecked",
            3,
        )
    });

    out.push(if h.code_signature {
        f(
            "code signature",
            State::On,
            "LC_CODE_SIGNATURE present",
            "the file is signed, though knife does not verify the chain",
            0,
        )
    } else {
        f(
            "code signature",
            State::Off,
            "no LC_CODE_SIGNATURE",
            "unsigned, so tampering leaves no signature to break",
            1,
        )
    });

    if h.restrict_segment {
        out.push(f(
            "__RESTRICT",
            State::On,
            "__RESTRICT segment present",
            "DYLD_INSERT_LIBRARIES injection is refused",
            0,
        ));
    }

    if let Some(s) = bin.sections.iter().find(|s| s.is_wx()) {
        out.push(f(
            "W^X",
            State::Off,
            format!("section {} is writable and executable", s.name),
            "a writable code page is a ready-made place to stage shellcode",
            3,
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Arch, LoadConfig};

    fn blank(format: Format) -> Binary {
        let mut b = Binary::stub(format, Arch::X86_64);
        b.entry = 0x1000;
        b.image_base = 0x1_4000_0000;
        b
    }

    fn state_of(r: &Report, name: &str) -> State {
        r.findings.iter().find(|f| f.name == name).unwrap().state
    }

    #[test]
    fn pe_aslr_without_relocations_is_only_partial() {
        // The header asks for ASLR but nothing can be rewritten, so the image
        // still lands at its preferred base. Reporting this as "enabled" is the
        // exact mistake this audit exists to avoid.
        let mut bin = blank(Format::Pe);
        bin.hardening.dll_characteristics = Some(DYNAMIC_BASE | NX_COMPAT);
        let r = run(&bin);
        assert_eq!(state_of(&r, "ASLR"), State::Partial);
    }

    #[test]
    fn pe_cfg_flag_without_a_guard_table_is_not_real() {
        let mut bin = blank(Format::Pe);
        bin.hardening.dll_characteristics = Some(GUARD_CF);
        bin.hardening.load_config = Some(LoadConfig {
            guard_flags: GUARD_CF_INSTRUMENTED,
            guard_cf_count: 0,
            ..Default::default()
        });
        assert_eq!(state_of(&run(&bin), "CFG"), State::Partial);
    }

    #[test]
    fn pe_safeseh_is_not_applicable_on_64_bit() {
        let bin = blank(Format::Pe);
        assert_eq!(state_of(&run(&bin), "SafeSEH"), State::NotApplicable);
    }

    #[test]
    fn elf_missing_gnu_stack_counts_as_executable() {
        // Absent PT_GNU_STACK is worse than a present RW one: the loader falls
        // back to an executable stack.
        let mut bin = blank(Format::Elf);
        bin.hardening.gnu_stack_exec = None;
        assert_eq!(state_of(&run(&bin), "NX"), State::Off);
    }

    #[test]
    fn elf_relro_without_bind_now_is_partial() {
        let mut bin = blank(Format::Elf);
        bin.hardening.gnu_relro = true;
        bin.hardening.bind_now = false;
        assert_eq!(state_of(&run(&bin), "RELRO"), State::Partial);

        bin.hardening.bind_now = true;
        assert_eq!(state_of(&run(&bin), "RELRO"), State::On);
    }

    #[test]
    fn a_fully_hardened_elf_scores_clean() {
        let mut bin = blank(Format::Elf);
        bin.hardening = HardeningFacts {
            gnu_stack_exec: Some(false),
            gnu_relro: true,
            bind_now: true,
            has_interp: true,
            elf_type: 3, // ET_DYN + not a lib == PIE executable
            stack_chk: true,
            fortify_syms: 12,
            ..Default::default()
        };
        let r = run(&bin);
        assert_eq!(r.exposure, Exposure::Hardened);
        assert_eq!(r.missing, 0);
    }

    #[test]
    fn a_bare_elf_scores_bare() {
        let mut bin = blank(Format::Elf);
        bin.hardening.gnu_stack_exec = Some(true); // exec stack, no PIE,
        let r = run(&bin); // no RELRO, no canary, no fortify
        assert_eq!(r.exposure, Exposure::Bare);
    }

    #[test]
    fn macho_pie_flag_is_read_from_the_header() {
        let mut bin = blank(Format::MachO);
        bin.hardening.macho_flags = Some(MH_PIE);
        assert_eq!(state_of(&run(&bin), "PIE"), State::On);
    }
}
