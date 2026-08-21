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
}

impl Session {
    /// Load one analysis workspace. `need` identifies the requesting feature
    /// in unsupported-architecture diagnostics.
    pub fn open(file: &str, db_path: Option<&str>, budget: usize, need: &str) -> Result<Session> {
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
        if !disasm::supported(bin.arch) {
            anyhow::bail!(
                "{need} needs x86/x64 disassembly; this is {}",
                bin.arch.label()
            );
        }
        let workspace_sha256 = hashes::sha256_hex(&bytes);
        let an = cache::load_or_analyze(&bin, &bytes, budget, &store, &workspace_sha256);
        Ok(Session {
            bin,
            bytes,
            db: store,
            an,
        })
    }
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
