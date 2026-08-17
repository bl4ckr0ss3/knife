//! Persistent derived-analysis cache.
//!
//! Names and notes remain in the human-readable analysis database. This cache
//! contains only facts Knife can reproduce from the binary: functions, CFGs,
//! instructions and xrefs. It is therefore always safe to discard.

use super::engine::{self, Analysis};
use crate::{db::Db, model::Binary};
use bincode::config;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const SCHEMA: u32 = 1;
const MAGIC: &[u8; 8] = b"KNFANLYS";

#[derive(Deserialize)]
struct CacheFile {
    magic: [u8; 8],
    schema: u32,
    knife_version: String,
    binary_sha256: String,
    budget: u64,
    names_digest: [u8; 32],
    analysis: Analysis,
}

#[derive(Serialize)]
struct CacheFileRef<'a> {
    magic: [u8; 8],
    schema: u32,
    knife_version: &'static str,
    binary_sha256: &'a str,
    budget: u64,
    names_digest: [u8; 32],
    analysis: &'a Analysis,
}

/// Load a compatible analysis or compute and atomically cache a fresh one.
pub fn load_or_analyze(
    bin: &Binary,
    bytes: &[u8],
    budget: usize,
    db: &Db,
    binary_sha256: &str,
) -> Analysis {
    if std::env::var_os("KNIFE_NO_CACHE").is_some() {
        return engine::analyze(bin, bytes, budget, db);
    }

    let path = cache_path(db, binary_sha256);
    let digest = names_digest(db);
    if let Some(mut analysis) = load(&path, binary_sha256, budget, digest) {
        analysis.rebuild_indexes();
        return analysis;
    }

    let analysis = engine::analyze(bin, bytes, budget, db);
    let _ = save(&path, binary_sha256, budget, digest, &analysis);
    analysis
}

fn load(
    path: &Path,
    binary_sha256: &str,
    budget: usize,
    names_digest: [u8; 32],
) -> Option<Analysis> {
    if std::fs::metadata(path).ok()?.len() > 1_073_741_824 {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let cfg = config::standard().with_limit::<1_073_741_824>();
    let (cached, _): (CacheFile, usize) = bincode::serde::decode_from_slice(&bytes, cfg).ok()?;
    if &cached.magic != MAGIC
        || cached.schema != SCHEMA
        || cached.knife_version != env!("CARGO_PKG_VERSION")
        || cached.binary_sha256 != binary_sha256
        || cached.budget != budget as u64
        || cached.names_digest != names_digest
    {
        return None;
    }
    Some(cached.analysis)
}

fn save(
    path: &Path,
    binary_sha256: &str,
    budget: usize,
    names_digest: [u8; 32],
    analysis: &Analysis,
) -> std::io::Result<()> {
    let cached = CacheFileRef {
        magic: *MAGIC,
        schema: SCHEMA,
        knife_version: env!("CARGO_PKG_VERSION"),
        binary_sha256,
        budget: budget as u64,
        names_digest,
        analysis,
    };
    let cfg = config::standard();
    let encoded = bincode::serde::encode_to_vec(cached, cfg)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("bin.{}.tmp", std::process::id()));
    std::fs::write(&tmp, encoded)?;
    // Windows rename does not replace an existing file. This is derived data,
    // so a small replacement window is preferable to leaving an invalid cache
    // permanently stuck. A missing cache merely causes fresh analysis.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(tmp, path)
}

fn cache_path(db: &Db, binary_sha256: &str) -> PathBuf {
    let dir = std::env::var_os("KNIFE_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| db.path().and_then(Path::parent).map(|p| p.join("cache")))
        .unwrap_or_else(|| crate::db::store_dir().join("cache"));
    dir.join(format!("{binary_sha256}.analysis-v{SCHEMA}.bin"))
}

fn names_digest(db: &Db) -> [u8; 32] {
    let mut hash = Sha256::new();
    for (address, name) in &db.names {
        hash.update(address.to_le_bytes());
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::hashes;

    fn fixture(tag: &str) -> (PathBuf, Binary, Vec<u8>, Db, String) {
        let root =
            std::env::temp_dir().join(format!("knife-analysis-cache-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture", &bytes).unwrap();
        let sha = hashes::sha256_hex(&bytes);
        let db_path = root.join("annotations.json");
        let db = Db::load(&sha, "fixture", db_path.to_str()).unwrap();
        (root, bin, bytes, db, sha)
    }

    #[test]
    fn analysis_round_trips_and_rebuilds_lookup_indexes() {
        let (root, bin, bytes, db, sha) = fixture("roundtrip");
        let fresh = load_or_analyze(&bin, &bytes, 10_000, &db, &sha);
        assert!(!fresh.functions.is_empty());
        let entry = fresh.functions[0].addr;
        let name = fresh.functions[0].name.clone();
        assert!(cache_path(&db, &sha).is_file());

        let cached = load_or_analyze(&bin, &bytes, 10_000, &db, &sha);
        assert_eq!(cached.functions.len(), fresh.functions.len());
        assert_eq!(cached.find_function(entry).map(|f| f.addr), Some(entry));
        assert_eq!(cached.find_by_name(&name).map(|f| f.addr), Some(entry));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_user_function_name_invalidates_and_replaces_the_cache() {
        let (root, bin, bytes, mut db, sha) = fixture("names");
        let fresh = load_or_analyze(&bin, &bytes, 10_000, &db, &sha);
        let entry = fresh.functions[0].addr;

        db.set_name(entry, "user_entry");
        let refreshed = load_or_analyze(&bin, &bytes, 10_000, &db, &sha);
        assert_eq!(
            refreshed.find_by_name("user_entry").map(|f| f.addr),
            Some(entry)
        );
        assert!(cache_path(&db, &sha).is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn staged_workspace_bytes_use_a_distinct_cache_identity() {
        let (root, original_bin, original, mut db, original_sha) = fixture("patch");
        let original_analysis =
            load_or_analyze(&original_bin, &original, 10_000, &db, &original_sha);
        assert!(!original_analysis.functions.is_empty());

        let offset = engine::va_to_off(
            &original_bin,
            engine::display_base(&original_bin),
            original_bin.entry,
        )
        .expect("fixture entry maps to file bytes");
        let replacement = original[offset] ^ 1;
        db.stage_patch(&original, offset as u64, &[replacement])
            .unwrap();
        let patched = db.apply_patches(&original).unwrap();
        let patched_sha = hashes::sha256_hex(&patched);
        assert_ne!(patched_sha, original_sha);
        let patched_bin = crate::formats::analyze("fixture", &patched).unwrap();
        let _ = load_or_analyze(&patched_bin, &patched, 10_000, &db, &patched_sha);

        let original_path = cache_path(&db, &original_sha);
        let patched_path = cache_path(&db, &patched_sha);
        assert_ne!(original_path, patched_path);
        assert!(original_path.is_file());
        assert!(patched_path.is_file());
        let _ = std::fs::remove_dir_all(root);
    }
}
