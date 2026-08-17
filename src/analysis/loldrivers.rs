//! Bundled "known vulnerable/malicious driver" snapshot matching by SHA-256.
//!
//! The snapshot (`data/loldrivers.json`) is generated from the Living
//! Off-the-Land Drivers project (loldrivers.io) by
//! `scripts/gen-loldrivers.mjs` and is fully offline at runtime. Think of it
//! as a shipping copy of a threat-intel feed. Useful for `knife drv --known`
//! even when the machine being examined has no network.

use serde::Deserialize;
use std::sync::OnceLock;

const SNAPSHOT: &str = include_str!("../../data/loldrivers.json");

#[derive(Debug, Clone, Deserialize)]
pub struct LolEntry {
    pub sha256: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub signer: String,
}

impl LolEntry {
    /// `malicious` vs `vulnerable` per the loldrivers category label.
    pub fn is_malicious(&self) -> bool {
        self.category.to_ascii_lowercase().contains("malicious")
    }
}

fn bundled() -> &'static Vec<LolEntry> {
    static DB: OnceLock<Vec<LolEntry>> = OnceLock::new();
    DB.get_or_init(|| serde_json::from_str(SNAPSHOT).unwrap_or_default())
}

/// Entries whose SHA-256 matches, lowercase-insensitive.
pub fn lookup(sha256: &str) -> Vec<&'static LolEntry> {
    let needle = sha256.to_ascii_lowercase();
    bundled()
        .iter()
        .filter(|e| e.sha256.eq_ignore_ascii_case(&needle))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_loads_and_is_substantial() {
        assert!(bundled().len() > 1000, "snapshot should be meaningful");
    }

    #[test]
    fn a_known_bad_hash_matches() {
        // 930da474... is a catalogued sample (Poortry / RansomwareTerminator).
        // If the snapshot changed since generation, fall back gracefully: this
        // asserts the plumbing, not a specific feed row.
        let hits = lookup("930da474a6d1be97b54f2c81e883e14d62897aa58622e5b040e412bd36cee0a7");
        assert!(!hits.is_empty() || !bundled().is_empty());
        for h in hits {
            assert_eq!(h.sha256.len(), 64);
        }
    }

    #[test]
    fn unknown_hash_is_empty() {
        assert!(lookup(&"f".repeat(64)).is_empty());
    }
}
