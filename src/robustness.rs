//! The promise that knife never crashes on a hostile file.
//!
//! Every input this tool sees is by definition untrusted: the whole job is
//! pulling apart binaries someone else built, often ones built to break
//! parsers. A panic on a malformed file is the worst kind of first impression,
//! so this harness throws the shapes an attacker would at the entire pipeline
//! (parse, recover, audit, render) and asserts only one thing: it returns,
//! whether Ok or Err, without unwinding.
//!
//! The generators are deliberately deterministic. A fuzzer that needs a corpus
//! and a nightly toolchain is a fine second line, but a reproducible test that
//! runs on every `cargo test` is what keeps a regression from ever landing.

#![cfg(test)]

use crate::analysis::{audit, driver, engine, hardening, ir, sinks};
use crate::db::Db;
use crate::listing;
use crate::model::Binary;

/// A tiny reproducible PRNG. `Date`/`rand` are avoided so a failure always
/// reproduces from the same seed.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        // Numerical Recipes constants.
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
    fn upto(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() >> 33) as usize % n
        }
    }
}

/// Run the whole analysis pipeline on a buffer. The point is that this returns
/// for any input at all; the results are not inspected.
fn exercise(bytes: &[u8]) {
    let Ok(bin) = crate::formats::analyze("torture", bytes) else {
        return; // a rejected file is a fine outcome; a panic is not
    };
    run_analyzers(&bin, bytes);
}

/// The parts that only apply once a file parsed. Split out so the fixture-based
/// tests can call it on a known-good `Binary` too.
fn run_analyzers(bin: &Binary, bytes: &[u8]) {
    let _ = hardening::run(bin);
    let _ = sinks::cluster(&[]);

    // A small budget keeps the torture loop quick while still walking real
    // recovery, cross-referencing, and rendering.
    let an = engine::analyze(bin, bytes, 20_000, &Db::default());
    let _ = sinks::find(&an);
    let _ = audit::run(&an, bin, bytes);

    let base = engine::display_base(bin);
    let strings = listing::string_map(bin, bytes, base);
    for f in an.functions.iter().take(50) {
        let _ = listing::function(&an, f, &Db::default(), base, &strings, None);
    }
    // The decompiler is the one heavy recursive pass the other exercisers skip;
    // a hostile file that drives expression propagation deep depends on it
    // staying bounded, so it gets the same never-unwind guarantee here.
    for f in an.functions.iter().take(50) {
        let _ = ir::decompile(&an, bin, f, &strings, &Db::default());
    }
    // The driver pass runs the dispatch scan, reachability BFS, sink walk and
    // signing parse. All of it must be panic-free on hostile input too.
    let _ = driver::report(bin, bytes, &an, &strings);
    // The data view takes an arbitrary address; feed it the entry and a couple
    // of edge addresses to exercise its bounds handling.
    for a in [bin.entry, 0, u64::MAX, bin.image_base] {
        let _ = listing::data_view(bin, base, bytes, a);
    }
}

#[test]
fn random_buffers_never_panic() {
    let mut rng = Lcg(0x1234_5678_9abc_def0);
    for _ in 0..2000 {
        let len = rng.upto(512);
        let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        exercise(&buf);
    }
}

#[test]
fn tiny_buffers_never_panic() {
    // Off-by-one and empty-slice mistakes live at these sizes.
    for len in 0..80usize {
        exercise(&vec![0u8; len]);
        exercise(&vec![0xffu8; len]);
    }
}

#[test]
fn plausible_headers_over_garbage_never_panic() {
    // A valid-looking magic followed by rubbish drives each format parser deep
    // into its structure-walking code before it gives up, which is where the
    // interesting crashes hide.
    let magics: &[&[u8]] = &[
        b"MZ",
        b"\x7fELF",
        &[0xfe, 0xed, 0xfa, 0xce], // Mach-O 32 BE
        &[0xfe, 0xed, 0xfa, 0xcf], // Mach-O 64 BE
        &[0xcf, 0xfa, 0xed, 0xfe], // Mach-O 64 LE
        &[0xca, 0xfe, 0xba, 0xbe], // fat Mach-O
        b"!<arch>\n",
    ];
    let mut rng = Lcg(0xdead_beef_cafe_f00d);
    for m in magics {
        for _ in 0..200 {
            let len = rng.upto(1024);
            let mut buf = m.to_vec();
            buf.extend((0..len).map(|_| rng.byte()));
            exercise(&buf);
        }
    }
}

/// Every prefix of a good file: catches structure offsets read without a bound.
#[test]
fn truncations_of_good_files_never_panic() {
    for good in fixtures() {
        // Every length is cheap enough for these small fixtures.
        for n in 0..good.len() {
            exercise(&good[..n]);
        }
    }
}

/// Single-byte corruption at every offset of a good file: catches fields
/// trusted because the rest of the header was well formed.
#[test]
fn bit_flips_of_good_files_never_panic() {
    let mut rng = Lcg(0x0badf00d_12345678);
    for good in fixtures() {
        for off in 0..good.len() {
            let mut buf = good.clone();
            buf[off] ^= 1 << (rng.upto(8));
            exercise(&buf);
            // Also try turning a length/rva field to a large value.
            let mut big = good.clone();
            big[off] = 0xff;
            exercise(&big);
        }
    }
}

fn fixtures() -> Vec<Vec<u8>> {
    use crate::formats::fixture::*;
    vec![
        elf_with_plt_call(),
        elf_aarch64_call(),
        elf_aarch64_plt_call(),
        elf_with_eh_frame_hdr(),
        pe_with_iat_call(),
        pe_with_driver(),
        macho_with_bind(),
    ]
}

#[test]
fn signing_walkers_never_panic_on_junk() {
    // `signing::summarize` reads a PE certificate table through `sig_region`;
    // throw arbitrary DER-shaped buffers and both a valid and an out-of-bounds
    // region at it. The result is not inspected. It must simply not unwind.
    use crate::analysis::signing;
    use crate::model::{Arch, Format};
    let mut rng = Lcg(0xdecafbad_01234567);
    for _ in 0..400 {
        let len = rng.upto(1536);
        let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let mut sbin = Binary::stub(Format::Pe, Arch::X86_64);
        sbin.sig_region = Some((0, len as u64));
        let _ = signing::summarize(&sbin, &buf);
        // An in-bounds offset with an oversized/truncated span.
        if len >= 8 {
            sbin.sig_region = Some(((len / 2) as u64, 4096));
            let _ = signing::summarize(&sbin, &buf);
        }
        // An offset beyond the buffer.
        sbin.sig_region = Some((len as u64 + 64, 64));
        let _ = signing::summarize(&sbin, &buf);
    }
}
