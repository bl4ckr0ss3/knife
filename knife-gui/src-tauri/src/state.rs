//! The loaded workspace and its derived caches, behind a panic barrier.
//!
//! Modeled on `reknife`'s MCP server (`src/mcp.rs`): one cached analysis session
//! behind a request dispatcher, with every engine call wrapped in
//! `catch_unwind`. knife parses hostile binaries — a malformed sample that
//! unwinds the engine must produce an error, never take the window down.
//!
//! Expensive, name-independent derivations (the string map) are built once at
//! load. Name-dependent derivations (driver hints, the audit findings, the
//! detail panel) are rebuilt after an edit that changes recovery.

use crate::dto;
use anyhow::{anyhow, Result};
use reknife::analysis::strings::Located;
use reknife::analysis::{audit, capabilities, driver, engine, hardening, hashes, signing, triage};
use reknife::listing;
use reknife::workspace::Session;
use reknife::ANALYSIS_BUDGET;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One open target: the analysis session plus everything the views read that is
/// too expensive to rebuild per request.
pub struct Loaded {
    pub path: PathBuf,
    pub session: Session,
    /// Display base: converts a shown virtual address into the space `Db` stores.
    pub base: u64,
    /// String literals keyed by address — built once (name-independent).
    pub strings: BTreeMap<u64, Located>,
    /// Driver listing hints, when the target is a plausible driver.
    pub hints: Option<BTreeMap<u64, String>>,
    /// Ranked attack-surface findings, canonically sorted.
    pub findings: Vec<audit::Finding>,
    /// The detail panel, pre-serialized (hashing a large image is not free).
    pub detail: serde_json::Value,
}

/// The shared backend state: at most one loaded target for now.
#[derive(Default)]
pub struct AppState {
    inner: Mutex<Option<Loaded>>,
}

impl AppState {
    /// Load a target (or reuse it if the same path is already open). All of the
    /// analysis, including the derived caches, happens inside one panic barrier.
    ///
    /// `phase` is called as each stage begins. Recovering functions in a large
    /// image takes seconds, and a window that says nothing for that long looks
    /// hung; naming the stage costs nothing and tells the truth.
    pub fn open(&self, path: &str, phase: &dyn Fn(&str)) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if guard.as_ref().is_some_and(|l| l.path == Path::new(path)) {
            return Ok(());
        }
        let loaded = catch_unwind(AssertUnwindSafe(|| -> Result<Loaded> {
            phase("parsing and recovering functions");
            let session = Session::open(path, None, ANALYSIS_BUDGET, "the graphical view")?;
            let base = engine::display_base(&session.bin);
            phase("mapping string literals");
            let strings = listing::string_map(&session.bin, &session.bytes, base);
            let mut loaded = Loaded {
                path: PathBuf::from(path),
                session,
                base,
                strings,
                hints: None,
                findings: Vec::new(),
                detail: serde_json::Value::Null,
            };
            recompute_derived_with(&mut loaded, phase);
            Ok(loaded)
        }))
        .map_err(|_| anyhow!("the analysis panicked while loading this file"))??;
        *guard = Some(loaded);
        Ok(())
    }

    /// Read the loaded workspace, panic-contained. Errors if nothing is open.
    pub fn read<T>(&self, f: impl FnOnce(&Loaded) -> Result<T>) -> Result<T> {
        let guard = self.inner.lock().unwrap();
        let loaded = guard.as_ref().ok_or_else(|| anyhow!("no target is open"))?;
        catch_unwind(AssertUnwindSafe(|| f(loaded)))
            .map_err(|_| anyhow!("the analysis panicked"))?
    }

    /// Persist an analyst fact that does not change recovery (a note). Saves the
    /// database; no re-analysis, so a comment on a huge image is instant.
    pub fn annotate<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        let mut guard = self.inner.lock().unwrap();
        let loaded = guard.as_mut().ok_or_else(|| anyhow!("no target is open"))?;
        catch_unwind(AssertUnwindSafe(|| {
            let out = f(&mut loaded.session)?;
            loaded.session.db.save()?;
            Ok::<T, anyhow::Error>(out)
        }))
        .map_err(|_| anyhow!("the edit panicked"))?
    }

    /// Persist an analyst fact that changes recovery (a name), then rebuild the
    /// analysis and the name-dependent caches — the GUI equivalent of the TUI's
    /// `refresh_analysis`. Uses `ANALYSIS_BUDGET` so the on-disk cache stays valid.
    pub fn edit<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        let mut guard = self.inner.lock().unwrap();
        let loaded = guard.as_mut().ok_or_else(|| anyhow!("no target is open"))?;
        let out = catch_unwind(AssertUnwindSafe(|| {
            let out = f(&mut loaded.session)?;
            loaded.session.db.save()?;
            Ok::<T, anyhow::Error>(out)
        }))
        .map_err(|_| anyhow!("the edit panicked"))??;
        let an = engine::analyze(
            &loaded.session.bin,
            &loaded.session.bytes,
            ANALYSIS_BUDGET,
            &loaded.session.db,
        );
        loaded.session.an = an;
        recompute_derived(loaded);
        Ok(out)
    }
}

/// Rebuild the name-dependent caches from the current analysis.
fn recompute_derived(loaded: &mut Loaded) {
    recompute_derived_with(loaded, &|_| {});
}

/// As `recompute_derived`, reporting each stage as it starts.
fn recompute_derived_with(loaded: &mut Loaded, phase: &dyn Fn(&str)) {
    let session = &loaded.session;
    phase("auditing call sites");
    let hints = driver::plausibly_a_driver(&session.bin)
        .then(|| driver::listing_hints(&session.bin, &session.bytes, &session.an));
    let mut findings = audit::run(&session.an, &session.bin, &session.bytes);
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.reachable.cmp(&a.reachable))
            .then(a.addr.cmp(&b.addr))
    });
    phase("hashing and reading mitigations");
    let detail = build_detail(session);
    loaded.hints = hints;
    loaded.findings = findings;
    loaded.detail = detail;
}

/// Assemble the right-hand detail panel: identity, sections, hashes, exploit
/// mitigations, the triage verdict, and signing.
fn build_detail(s: &Session) -> serde_json::Value {
    let file_hashes = hashes::file_hashes(&s.bytes);
    let imphash = hashes::imphash(&s.bin);
    let hardening = hardening::run(&s.bin);
    let caps = capabilities::matches(
        s.bin
            .all_imported_functions()
            .chain(s.bin.exports.iter().map(String::as_str)),
    );
    let no_yara: Vec<String> = Vec::new();
    let verdict = triage::run(&s.bin, &caps, &no_yara);
    let signing = signing::summarize(&s.bin, &s.bytes);
    let named = s.an.functions.iter().filter(|f| f.named).count();

    let detail = dto::BinaryDetail {
        path: s.bin.path.clone(),
        format: s.bin.format.label().to_string(),
        arch: s.bin.arch.label().to_string(),
        bits: s.bin.bits,
        size: s.bin.size,
        image_base: dto::hex(s.bin.image_base),
        entry: dto::hex(s.bin.entry),
        subsystem: s.bin.subsystem.clone(),
        is_lib: s.bin.is_lib,
        is_stripped: s.bin.is_stripped,
        functions: s.an.functions.len(),
        named,
        sections: dto::sections(&s.bin),
        hashes: dto::HashesDto {
            md5: file_hashes.md5,
            sha1: file_hashes.sha1,
            sha256: file_hashes.sha256,
            imphash,
        },
        mitigations: dto::mitigations(&hardening),
        triage: dto::triage(&verdict),
        signing: dto::SigningDto {
            signed: signing.signed,
            entries: signing.entries,
            subjects: signing.subjects,
            thumbprints: signing.thumbprints,
        },
    };
    serde_json::to_value(detail).unwrap_or(serde_json::Value::Null)
}
