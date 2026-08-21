//! Terminal rendering. One accent (violet), warm greys, colour tied to meaning.

use crate::analysis::triage::{TriageResult, Verdict};
use owo_colors::{OwoColorize, Style};
use std::io::{self, BufWriter, StdoutLock, Write};

/// Block-buffered stdout, for the commands that print in bulk.
///
/// `println!` flushes at every newline, which is one write syscall per line.
/// A 300 MB image yields over two million strings, and at that size the
/// flushing costs several times what finding them did. Bulk printers write
/// here and let the buffer decide when to talk to the operating system.
pub fn bulk() -> BufWriter<StdoutLock<'static>> {
    BufWriter::with_capacity(256 * 1024, io::stdout().lock())
}

/// Flush a bulk writer and hand back any real failure.
///
/// A closed pipe is not one: `knife strings big.dll | head` is the reader
/// getting exactly what it asked for, and reporting that as an error would be
/// wrong. Buffering makes this reachable where line-at-a-time printing simply
/// panicked, so it is handled rather than propagated.
pub fn finish(mut out: impl Write) -> anyhow::Result<()> {
    match out.flush() {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

/// Whether a failure is just a reader that stopped listening.
pub fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(|io| io.kind() == io::ErrorKind::BrokenPipe)
}

pub fn human(bytes: u64) -> String {
    if bytes >= 1 << 20 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1 << 10 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// palette
pub fn accent() -> Style {
    Style::new().truecolor(0xe0, 0x55, 0x55)
}
pub fn muted() -> Style {
    Style::new().truecolor(0x9b, 0x94, 0xae)
}
pub fn faint() -> Style {
    Style::new().truecolor(0x79, 0x72, 0x8f)
}
pub fn mint() -> Style {
    Style::new().truecolor(0x7f, 0xd4, 0xc1)
}
pub fn amber() -> Style {
    Style::new().truecolor(0xe0, 0xa8, 0x78)
}
pub fn red() -> Style {
    Style::new().truecolor(0xe0, 0x8a, 0x94)
}

pub fn kind_style(kind: &str) -> Style {
    match kind {
        "bad" => red(),
        "warn" => amber(),
        _ => mint(),
    }
}

/// Bracketed status marker in the classic tool style:
/// `[-]` bad, `[=]` warning, `[+]` informational/good, `[ ]` not applicable.
pub fn marker(kind: &str) -> &'static str {
    match kind {
        "bad" => "[-]",
        "warn" => "[=]",
        "na" => "[ ]",
        _ => "[+]",
    }
}

pub fn verdict_style(v: Verdict) -> Style {
    match v {
        Verdict::Clean => mint(),
        Verdict::LowRisk => muted(),
        Verdict::Suspicious => amber(),
        Verdict::Malicious => red(),
    }
}

pub fn entropy_style(e: f64) -> Style {
    if e >= 7.2 {
        red()
    } else if e >= 6.0 {
        amber()
    } else {
        mint()
    }
}

/// A fixed-width entropy bar, 0..8 → `width` cells.
pub fn entropy_bar(e: f64, width: usize) -> String {
    let filled = ((e / 8.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let mut s = String::new();
    for _ in 0..filled {
        s.push('█');
    }
    for _ in filled..width {
        s.push('░');
    }
    s
}

pub fn section_header(title: &str) {
    println!();
    println!(
        "{} {}",
        "▌".style(accent()),
        title.to_uppercase().style(accent()).bold()
    );
}

pub fn kv(key: &str, val: impl std::fmt::Display) {
    println!("  {:<12}{}", key.style(faint()), val);
}

pub fn kv_styled(key: &str, val: impl std::fmt::Display, style: Style) {
    println!("  {:<12}{}", key.style(faint()), val.style(style));
}

pub fn verdict_banner(t: &TriageResult) {
    let style = verdict_style(t.verdict);
    println!();
    println!(
        "  {}   {}",
        t.verdict.label().style(style).bold(),
        format!("risk score {}", t.score).style(faint())
    );
}
