//! The analysis database: what you worked out, kept between sessions.
//!
//! Everything else in knife is derived from the bytes and can be recomputed at
//! any time. This file holds the opposite: the facts only a person can supply,
//! a function's real name and a note about what it does. That is the difference
//! between reading a binary once and working on one over days.
//!
//! Three decisions shape the format:
//!
//! **Keyed by content, not by path.** The database is found by the file's
//! SHA-256, so renaming or moving the target keeps the work, and pointing knife
//! at a different build never silently applies the wrong names.
//!
//! **Addresses are stored base-relative.** What you see and type is the virtual
//! address, but what is written down is the offset from the image base, so a
//! database stays correct if the image is ever rebased.
//!
//! **The file is meant to be read.** Addresses are hex strings and entries are
//! a flat list, so a database can be diffed, hand-edited, and sent to someone
//! else without any tooling on their end.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One stored fact, as it appears on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    /// Base-relative address, written as hex so the file reads like the tool.
    at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OnDisk {
    /// Identity of the binary these annotations belong to.
    sha256: String,
    /// Last path the target was seen at. Informational: lookup is by hash.
    #[serde(default)]
    file: String,
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Default)]
pub struct Db {
    pub sha256: String,
    pub file: String,
    /// Base-relative address -> the name you gave it.
    pub names: BTreeMap<u64, String>,
    /// Base-relative address -> your note.
    pub notes: BTreeMap<u64, String>,
    path: Option<PathBuf>,
}

impl Db {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.notes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.names.len() + self.notes.len()
    }

    /// Where this database lives, once it has a home.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Load the database for a binary, or start an empty one.
    ///
    /// A missing file is not an error: the first annotation creates it. A
    /// corrupt one is an error, because silently discarding somebody's notes is
    /// worse than refusing to run.
    pub fn load(sha256: &str, file: &str, explicit: Option<&str>) -> Result<Db> {
        let path = match explicit {
            Some(p) => PathBuf::from(p),
            None => store_dir().join(format!("{sha256}.json")),
        };

        let mut db = Db {
            sha256: sha256.to_string(),
            file: file.to_string(),
            path: Some(path.clone()),
            ..Default::default()
        };

        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(db);
        };
        let disk: OnDisk = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a valid knife database", path.display()))?;

        // A database named for one binary but carrying another's hash means the
        // file was copied by hand; say so rather than applying the wrong names.
        if !disk.sha256.is_empty() && disk.sha256 != sha256 {
            anyhow::bail!(
                "{} belongs to a different binary (sha256 {}…, this file is {}…)",
                path.display(),
                &disk.sha256[..disk.sha256.len().min(12)],
                &sha256[..sha256.len().min(12)],
            );
        }

        for e in disk.entries {
            let Some(at) = parse_hex(&e.at) else { continue };
            if !e.name.is_empty() {
                db.names.insert(at, e.name);
            }
            if !e.note.is_empty() {
                db.notes.insert(at, e.note);
            }
        }
        Ok(db)
    }

    pub fn set_name(&mut self, at: u64, name: &str) {
        self.names.insert(at, name.to_string());
    }

    pub fn set_note(&mut self, at: u64, note: &str) {
        self.notes.insert(at, note.to_string());
    }

    /// Remove whatever is stored at an address. Returns what was there.
    pub fn clear(&mut self, at: u64) -> (Option<String>, Option<String>) {
        (self.names.remove(&at), self.notes.remove(&at))
    }

    /// Write the database out, creating its directory if needed.
    ///
    /// Writing goes through a temporary file and a rename, so an interrupted
    /// save cannot leave a half-written database where a complete one was.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
        }

        let mut addrs: Vec<u64> = self
            .names
            .keys()
            .chain(self.notes.keys())
            .copied()
            .collect();
        addrs.sort_unstable();
        addrs.dedup();

        let disk = OnDisk {
            sha256: self.sha256.clone(),
            file: self.file.clone(),
            entries: addrs
                .into_iter()
                .map(|at| Entry {
                    at: format!("0x{at:x}"),
                    name: self.names.get(&at).cloned().unwrap_or_default(),
                    note: self.notes.get(&at).cloned().unwrap_or_default(),
                })
                .collect(),
        };

        let text = serde_json::to_string_pretty(&disk)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).with_context(|| format!("cannot write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
    }
}

/// Where databases live when no path is given.
///
/// A central store is used rather than a file beside the target, because the
/// interesting targets are usually somewhere you cannot write: a system
/// directory, a mounted image, a read-only sample share.
pub fn store_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KNIFE_DB_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    if let Ok(d) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(d).join("knife");
    }
    #[cfg(target_os = "macos")]
    if let Ok(d) = std::env::var("HOME") {
        return PathBuf::from(d).join("Library/Application Support/knife");
    }
    if let Ok(d) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(d).join("knife");
    }
    if let Ok(d) = std::env::var("HOME") {
        return PathBuf::from(d).join(".local/share/knife");
    }
    PathBuf::from(".knife")
}

fn parse_hex(s: &str) -> Option<u64> {
    let t = s.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => t.parse::<u64>().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("knife-db-test-{tag}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn a_missing_database_is_empty_not_an_error() {
        let p = tmp_path("missing");
        let db = Db::load("abc123", "t.exe", Some(p.to_str().unwrap())).unwrap();
        assert!(db.is_empty());
    }

    #[test]
    fn annotations_survive_a_round_trip() {
        let p = tmp_path("roundtrip");
        let ps = p.to_str().unwrap().to_string();

        let mut db = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        db.set_name(0x1400, "parse_header");
        db.set_note(0x1444, "length is attacker controlled");
        db.save().unwrap();

        let back = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        assert_eq!(
            back.names.get(&0x1400).map(String::as_str),
            Some("parse_header")
        );
        assert_eq!(
            back.notes.get(&0x1444).map(String::as_str),
            Some("length is attacker controlled")
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_database_for_another_binary_is_refused() {
        // Applying one binary's names to another would be worse than useless:
        // it would look like analysis.
        let p = tmp_path("mismatch");
        let ps = p.to_str().unwrap().to_string();

        let mut db = Db::load("aaaaaaaaaaaaaaaa", "a.exe", Some(&ps)).unwrap();
        db.set_name(0x1000, "from_a");
        db.save().unwrap();

        let err = Db::load("bbbbbbbbbbbbbbbb", "b.exe", Some(&ps)).unwrap_err();
        assert!(
            err.to_string().contains("different binary"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn clearing_removes_both_name_and_note() {
        let p = tmp_path("clear");
        let ps = p.to_str().unwrap().to_string();
        let mut db = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        db.set_name(0x2000, "x");
        db.set_note(0x2000, "y");
        let (n, c) = db.clear(0x2000);
        assert_eq!(n.as_deref(), Some("x"));
        assert_eq!(c.as_deref(), Some("y"));
        assert!(db.is_empty());
    }

    #[test]
    fn the_stored_file_is_hex_and_hand_editable() {
        let p = tmp_path("hex");
        let ps = p.to_str().unwrap().to_string();
        let mut db = Db::load("abc123", "t.exe", Some(&ps)).unwrap();
        db.set_name(0x401000, "main");
        db.save().unwrap();

        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"0x401000\""), "addresses are hex: {text}");
        assert!(text.contains("\"main\""));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn hand_written_decimal_addresses_still_load() {
        // Somebody will edit this file by hand; accept the obvious alternative.
        let p = tmp_path("decimal");
        std::fs::write(
            &p,
            r#"{"sha256":"abc123","file":"t.exe","entries":[{"at":"4198400","name":"main"}]}"#,
        )
        .unwrap();
        let db = Db::load("abc123", "t.exe", Some(p.to_str().unwrap())).unwrap();
        assert_eq!(db.names.get(&0x401000).map(String::as_str), Some("main"));
        let _ = std::fs::remove_file(&p);
    }
}
