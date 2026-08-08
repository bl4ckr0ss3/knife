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
    pub notes: Vec<String>,
}

impl Binary {
    pub fn all_imported_functions(&self) -> impl Iterator<Item = &str> {
        self.imports
            .iter()
            .flat_map(|l| l.functions.iter().map(String::as_str))
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
