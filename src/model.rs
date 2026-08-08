//! The format-neutral model every analyzer fills in. Everything downstream
//! (triage, disasm target selection, JSON export) talks to this, not to goblin.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Format {
    Pe,
    Elf,
    MachO,
    Archive,
    Unknown,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Pe => "PE",
            Format::Elf => "ELF",
            Format::MachO => "Mach-O",
            Format::Archive => "archive",
            Format::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    Riscv,
    Other,
}

impl Arch {
    pub fn label(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86-64",
            Arch::Arm => "ARM",
            Arch::Aarch64 => "AArch64",
            Arch::Mips => "MIPS",
            Arch::Riscv => "RISC-V",
            Arch::Other => "other",
        }
    }
    /// Bit width used by the disassembler and pointer formatting.
    #[allow(dead_code)]
    pub fn bits(self) -> u32 {
        match self {
            Arch::X86 | Arch::Arm | Arch::Mips => 32,
            _ => 64,
        }
    }
    pub fn is_x86(self) -> bool {
        matches!(self, Arch::X86 | Arch::X86_64)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    pub file_off: u64,
    pub file_size: u64,
    pub entropy: f64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Section {
    pub fn flags(&self) -> String {
        format!(
            "{}{}{}",
            if self.read { "r" } else { "-" },
            if self.write { "w" } else { "-" },
            if self.exec { "x" } else { "-" },
        )
    }
    pub fn is_wx(&self) -> bool {
        self.write && self.exec
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportedLib {
    pub name: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SymKind {
    /// A defined function (has code at `addr`).
    Func,
    /// An exported function/symbol.
    Export,
    /// An imported function; `addr` is the IAT slot it is called through.
    Import,
    /// A forwarding stub that jumps through an import slot: an ELF `.plt` entry
    /// or a PE `jmp [IAT]` thunk. `addr` is the stub itself, which is what a
    /// `call` instruction targets, and `name` is the import it reaches.
    Thunk,
}

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    /// Image address (PE: RVA; ELF/Mach-O: virtual address).
    pub addr: u64,
    pub name: String,
    pub kind: SymKind,
}

/// The PE load configuration directory, where the linker records the pointers
/// that make stack cookies and Control Flow Guard work. Its presence is what
/// separates "the binary was built with the flag" from "the flag is in the
/// header but nothing backs it".
#[derive(Debug, Clone, Default, Serialize)]
pub struct LoadConfig {
    pub security_cookie: u64,
    pub seh_table: u64,
    pub seh_count: u64,
    pub guard_flags: u32,
    pub guard_cf_count: u64,
}

/// Raw container facts the mitigation audit reads. These are deliberately
/// facts, not verdicts: each format module records only what its headers
/// actually say, and `analysis::hardening` does all the interpreting, so the
/// exploitability reasoning lives in one place instead of three.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HardeningFacts {
    // ── PE ──
    pub dll_characteristics: Option<u16>,
    pub load_config: Option<LoadConfig>,

    // ── ELF ──
    /// PT_GNU_STACK present and marked executable. `None` means the header is
    /// absent entirely, which is its own finding: the loader then falls back to
    /// an executable stack.
    pub gnu_stack_exec: Option<bool>,
    pub gnu_relro: bool,
    pub bind_now: bool,
    pub textrel: bool,
    pub has_interp: bool,
    /// Raw `e_type`. ET_DYN (3) covers both PIE programs and shared libraries,
    /// so the audit reads it alongside `is_lib` rather than guessing from the
    /// load address.
    pub elf_type: u16,

    // ── Mach-O ──
    pub macho_flags: Option<u32>,
    pub code_signature: bool,
    pub restrict_segment: bool,

    // ── derived from the symbol surface, so cross-format ──
    /// `__stack_chk_fail` / `__stack_chk_guard` referenced.
    pub stack_chk: bool,
    /// Count of `_chk` fortified libc variants (`__memcpy_chk`, `__printf_chk`).
    pub fortify_syms: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Binary {
    pub path: String,
    pub size: u64,
    pub format: Format,
    pub arch: Arch,
    pub bits: u32,
    pub endian_little: bool,
    pub is_lib: bool,
    pub is_stripped: bool,
    pub entry: u64,
    pub image_base: u64,
    pub subsystem: Option<String>,
    pub timestamp: Option<i64>,
    pub sections: Vec<Section>,
    pub imports: Vec<ImportedLib>,
    pub exports: Vec<String>,
    /// Addressed symbols for the analysis engine (functions, exports, imports).
    pub symbols: Vec<Symbol>,
    /// Function-start addresses recovered from container metadata rather than
    /// from control flow: the PE exception directory, a prologue sweep. These
    /// are image-relative like `Symbol::addr`, carry no name, and exist so the
    /// engine can find code that is only ever reached through indirect calls,
    /// which is most of a stripped C++ binary.
    pub func_hints: Vec<u64>,
    pub libs: Vec<String>,
    pub rpaths: Vec<String>,
    pub overall_entropy: f64,
    pub overlay_off: Option<u64>,
    pub overlay_size: u64,
    pub overlay_entropy: f64,
    pub has_signature: bool,
    /// PE certificate table (file offset, size). It lives at end-of-file and
    /// must be excluded from overlay detection or every signed binary looks
    /// like it has a high-entropy appended payload.
    pub sig_region: Option<(u64, u64)>,
    /// Container facts for the exploit-mitigation audit (`knife sec`).
    pub hardening: HardeningFacts,
    pub notes: Vec<String>,
}

impl Binary {
    pub fn all_imported_functions(&self) -> impl Iterator<Item = &str> {
        self.imports
            .iter()
            .flat_map(|l| l.functions.iter().map(String::as_str))
    }

    /// A minimal `Binary` for tests to fill in selectively. Adding a field to
    /// the model should not mean editing every test fixture that happens to
    /// construct one.
    #[cfg(test)]
    pub fn stub(format: Format, arch: Arch) -> Binary {
        Binary {
            path: "stub".into(),
            size: 0,
            format,
            arch,
            bits: arch.bits(),
            endian_little: true,
            is_lib: false,
            is_stripped: false,
            entry: 0,
            image_base: 0,
            subsystem: None,
            timestamp: None,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            func_hints: Vec::new(),
            libs: Vec::new(),
            rpaths: Vec::new(),
            overall_entropy: 0.0,
            overlay_off: None,
            overlay_size: 0,
            overlay_entropy: 0.0,
            has_signature: false,
            sig_region: None,
            hardening: HardeningFacts::default(),
            notes: Vec::new(),
        }
    }

    /// The section that contains the entry point, if any.
    #[allow(dead_code)]
    pub fn entry_section(&self) -> Option<&Section> {
        let e = self.entry;
        self.sections
            .iter()
            .find(|s| s.vaddr <= e && e < s.vaddr + s.vsize.max(s.file_size))
    }
}
