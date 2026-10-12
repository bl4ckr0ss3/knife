//! Shared analyzed-workspace loader used by every Knife front end.

use crate::analysis::{cache, disasm, engine, hashes};
use crate::{db, formats, model::Binary};
use anyhow::{Context, Result};

/// A target after persistent staged patches and analyst facts have been
/// applied, parsed, and analyzed.
pub struct Session {
    pub bin: Binary,
    pub bytes: Vec<u8>,
    pub db: db::Db,
    pub an: engine::Analysis,
    /// Whether `an` carries recovered code. False when the architecture has
    /// no lifter (wasm, MIPS, …) and the session was opened data-only: read
    /// tools work off container facts, and code tools must refuse.
    pub code_analyzed: bool,
}

impl Session {
    /// Load one analysis workspace. `need` identifies the requesting feature
    /// in unsupported-architecture diagnostics.
    pub fn open(file: &str, db_path: Option<&str>, budget: usize, need: &str) -> Result<Session> {
        let mut s = Session::open_data(file, db_path)?;
        if !disasm::supported(s.bin.arch) {
            anyhow::bail!(
                "{need} needs x86, x64, or AArch64 disassembly; this is {}",
                s.bin.arch.label()
            );
        }
        s.an = cache::load_or_analyze(&s.bin, &s.bytes, budget, &s.db, &workspace_sha(&s.bytes));
        s.code_analyzed = true;
        Ok(s)
    }

    /// Load container facts without code analysis. Used by read-only views
    /// and by architectures the engine cannot lift: the parse, the staged
    /// patches, and the annotation database all behave exactly as `open`.
    pub fn open_data(file: &str, db_path: Option<&str>) -> Result<Session> {
        let original = std::fs::read(file).with_context(|| format!("cannot read {file}"))?;
        let original_bin = formats::analyze(file, &original)?;
        let sha256 = hashes::sha256_hex(&original);
        let store = db::Db::load(&sha256, file, db_path)?;
        let bytes = store.apply_patches(original)?;
        let bin = if store.patches.is_empty() {
            original_bin
        } else {
            formats::analyze(file, &bytes).context("staged patches make the binary unparsable")?
        };
        let an = engine::Analysis::empty(bin.arch);
        Ok(Session {
            bin,
            bytes,
            db: store,
            an,
            code_analyzed: false,
        })
    }
}

fn workspace_sha(bytes: &[u8]) -> String {
    hashes::sha256_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_session_applies_persistent_patch_before_analysis() {
        let root =
            std::env::temp_dir().join(format!("knife-shared-workspace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("fixture.elf");
        let database = root.join("fixture.json");
        let original = crate::formats::fixture::elf_with_plt_call();
        std::fs::write(&target, &original).unwrap();
        let bin = crate::formats::analyze("fixture.elf", &original).unwrap();
        let offset = engine::va_to_off(&bin, engine::display_base(&bin), bin.entry).unwrap();
        let replacement = original[offset] ^ 1;
        let sha256 = hashes::sha256_hex(&original);
        let mut db = db::Db::load(&sha256, target.to_str().unwrap(), database.to_str()).unwrap();
        db.stage_patch(&original, offset as u64, &[replacement])
            .unwrap();
        db.save().unwrap();

        let session =
            Session::open(target.to_str().unwrap(), database.to_str(), 10_000, "test").unwrap();
        assert_eq!(session.bytes[offset], replacement);
        assert_eq!(session.db.patches.len(), 1);
        assert!(!session.an.functions.is_empty());
        assert_eq!(std::fs::read(&target).unwrap(), original);
        let _ = std::fs::remove_dir_all(root);
    }
}
