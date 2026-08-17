//! Format detection and dispatch. goblin does the heavy parsing; these modules
//! flatten its per-format structures into our neutral `Binary` model.

mod elf;
#[doc(hidden)]
pub mod fixture;
mod macho;
mod pe;

use crate::analysis::entropy::entropy;
use crate::model::{Binary, Format, Section};
use anyhow::{bail, Result};
use goblin::Object;

#[allow(dead_code)]
pub fn detect(bytes: &[u8]) -> Format {
    match Object::parse(bytes) {
        Ok(Object::PE(_)) => Format::Pe,
        Ok(Object::Elf(_)) => Format::Elf,
        Ok(Object::Mach(_)) => Format::MachO,
        Ok(Object::Archive(_)) => Format::Archive,
        _ => Format::Unknown,
    }
}

pub fn analyze(path: &str, bytes: &[u8]) -> Result<Binary> {
    // goblin parses fully untrusted input, and on some malformed files it
    // panics (an unchecked subtraction on a crafted Mach-O, for one) rather
    // than returning an error. Since the whole job here is hostile input, the
    // parse runs inside a catch so a dependency panic becomes a clean rejection
    // instead of taking the process down. Our own analysis stays outside the
    // catch, so a bug in knife still surfaces as a panic in tests.
    let mut bin = catch_parse(path, bytes)?;
    bin.overall_entropy = entropy(bytes);
    detect_overlay(&mut bin, bytes.len() as u64, bytes);
    Ok(bin)
}

fn catch_parse(path: &str, bytes: &[u8]) -> Result<Binary> {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    // Suppress the default hook for the duration: a caught, expected panic on a
    // hostile file should not spray a backtrace across the user's terminal.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| build_from_object(path, bytes)));
    std::panic::set_hook(prev);

    match result {
        Ok(inner) => inner,
        Err(_) => bail!("malformed binary: the parser could not make sense of it"),
    }
}

fn build_from_object(path: &str, bytes: &[u8]) -> Result<Binary> {
    match Object::parse(bytes) {
        Ok(Object::PE(pe)) => Ok(pe::build(path, bytes, pe)),
        Ok(Object::Elf(elf)) => Ok(elf::build(path, bytes, elf)),
        Ok(Object::Mach(mach)) => macho::build(path, bytes, mach),
        Ok(Object::Archive(_)) => bail!("archive files are listed, not analyzed (try `knife ls`)"),
        _ => bail!("unrecognized format: not PE, ELF, or Mach-O"),
    }
}

/// Bytes past the end of the last mapped section: appended payload / bundle.
/// The Authenticode certificate table also lives here, so it is excluded: a
/// signature is not an overlay.
fn detect_overlay(bin: &mut Binary, file_len: u64, bytes: &[u8]) {
    let end = bin
        .sections
        .iter()
        .filter(|s| s.file_size > 0)
        .map(|s| s.file_off + s.file_size)
        .max()
        .unwrap_or(0);

    // Trim the trailing certificate table from what we treat as overlay.
    let mut effective_end = file_len;
    if let Some((coff, csize)) = bin.sig_region {
        // The cert table is normally the final region; drop everything from its
        // start onward when it reaches (near) EOF.
        if coff >= end && coff + csize >= file_len.saturating_sub(8) {
            effective_end = coff;
        }
    }

    if end > 0 && end < effective_end {
        let off = end as usize;
        let stop = effective_end as usize;
        bin.overlay_off = Some(end);
        bin.overlay_size = effective_end - end;
        bin.overlay_entropy = entropy(&bytes[off..stop]);
    }
}

/// Shared helper: fill entropy for a section from its file range.
pub(crate) fn section_entropy(bytes: &[u8], off: u64, size: u64) -> f64 {
    let off = off as usize;
    if off >= bytes.len() || size == 0 {
        return 0.0;
    }
    let end = (off + size as usize).min(bytes.len());
    entropy(&bytes[off..end])
}

/// List archive members without analyzing them.
pub fn list_archive(bytes: &[u8]) -> Result<Vec<(String, u64)>> {
    match Object::parse(bytes) {
        Ok(Object::Archive(ar)) => Ok(ar
            .members()
            .into_iter()
            .map(|m| {
                let size = ar.get(m).map(|e| e.size() as u64).unwrap_or(0);
                (m.to_string(), size)
            })
            .collect()),
        _ => bail!("not an archive"),
    }
}

// used by the per-format builders; the arguments mirror a section header, so a
// flat positional list reads more clearly than a one-off struct here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mk_section(
    name: impl Into<String>,
    vaddr: u64,
    vsize: u64,
    file_off: u64,
    file_size: u64,
    read: bool,
    write: bool,
    exec: bool,
    bytes: &[u8],
) -> Section {
    // Clamp the file-backed range to what the file actually contains. A crafted
    // header can claim a section that runs past EOF; if that claim is trusted,
    // every later offset computed from it walks off the end of the buffer. Once
    // clamped here, an offset derived from `file_off`/`file_size` is always in
    // bounds, which is what lets the rest of the tool index without a guard at
    // every site.
    let len = bytes.len() as u64;
    let file_off = file_off.min(len);
    let file_size = file_size.min(len - file_off);

    Section {
        name: name.into(),
        vaddr,
        vsize,
        file_off,
        file_size,
        entropy: section_entropy(bytes, file_off, file_size),
        read,
        write,
        exec,
    }
}
