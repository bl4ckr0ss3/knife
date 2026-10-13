//! Durable investigation state shared by interactive and agent clients.

use super::evidence::{EvidenceId, EvidenceRecord};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const SCHEMA: u32 = 1;
const MAX_ENTRIES: usize = 4096;
const MAX_TEXT: usize = 32 * 1024;
const MAX_FILE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Analyst,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub text: String,
    pub evidence: Vec<EvidenceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Open,
    Supported,
    Contradicted,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: u64,
    pub question: String,
    pub status: HypothesisStatus,
    pub supports: Vec<EvidenceId>,
    pub contradicts: Vec<EvidenceId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigation {
    schema: u32,
    pub target_sha256: String,
    pub messages: Vec<Message>,
    pub hypotheses: Vec<Hypothesis>,
    pub evidence: BTreeMap<String, EvidenceRecord>,
    #[serde(skip)]
    disk_revision: Option<String>,
}

impl Investigation {
    pub fn new(target_sha256: &str) -> Self {
        Self {
            schema: SCHEMA,
            target_sha256: target_sha256.into(),
            messages: Vec::new(),
            hypotheses: Vec::new(),
            evidence: BTreeMap::new(),
            disk_revision: None,
        }
    }

    pub fn load(path: &Path, target_sha256: &str) -> Result<Self> {
        let metadata = match std::fs::metadata(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::new(target_sha256))
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.len() > MAX_FILE {
            return Err(anyhow!("investigation exceeds 16 MiB"));
        }
        let encoded = std::fs::read(path)?;
        let mut value: Self = serde_json::from_slice(&encoded)?;
        value.disk_revision = Some(crate::analysis::hashes::sha256_hex(&encoded));
        if value.schema != SCHEMA || value.target_sha256 != target_sha256 {
            return Err(anyhow!(
                "investigation schema or target identity does not match"
            ));
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.messages.len() > MAX_ENTRIES
            || self.hypotheses.len() > MAX_ENTRIES
            || self.evidence.len() > MAX_ENTRIES
        {
            return Err(anyhow!("investigation entry limit reached"));
        }
        for message in &self.messages {
            check_text(&message.text)?;
            self.check_links(&message.evidence)?;
        }
        for hypothesis in &self.hypotheses {
            check_text(&hypothesis.question)?;
            self.check_links(&hypothesis.supports)?;
            self.check_links(&hypothesis.contradicts)?;
        }
        for (id, record) in &self.evidence {
            if id != &record.id.0 {
                return Err(anyhow!("invalid evidence index"));
            }
        }
        Ok(())
    }

    fn check_links(&self, ids: &[EvidenceId]) -> Result<()> {
        if ids.iter().any(|id| !self.evidence.contains_key(&id.0)) {
            return Err(anyhow!("unknown evidence link"));
        }
        Ok(())
    }

    pub fn append(&mut self, role: Role, text: String, evidence: Vec<EvidenceId>) -> Result<()> {
        check_text(&text)?;
        self.check_links(&evidence)?;
        if self.messages.len() >= MAX_ENTRIES {
            return Err(anyhow!("conversation entry limit reached"));
        }
        self.messages.push(Message {
            role,
            text,
            evidence,
        });
        Ok(())
    }

    pub fn ask(&mut self, question: String) -> Result<u64> {
        check_text(&question)?;
        if self.hypotheses.len() >= MAX_ENTRIES {
            return Err(anyhow!("hypothesis entry limit reached"));
        }
        let id = self
            .hypotheses
            .iter()
            .map(|h| h.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow!("hypothesis ID exhausted"))?;
        self.hypotheses.push(Hypothesis {
            id,
            question,
            status: HypothesisStatus::Open,
            supports: Vec::new(),
            contradicts: Vec::new(),
        });
        Ok(id)
    }

    pub fn record(&mut self, evidence: EvidenceRecord) -> Result<()> {
        if self.evidence.len() >= MAX_ENTRIES && !self.evidence.contains_key(&evidence.id.0) {
            return Err(anyhow!("evidence entry limit reached"));
        }
        self.evidence.insert(evidence.id.0.clone(), evidence);
        Ok(())
    }

    pub fn link(&mut self, hypothesis: u64, evidence: EvidenceId, contradicts: bool) -> Result<()> {
        self.check_links(std::slice::from_ref(&evidence))?;
        let hypothesis = self
            .hypotheses
            .iter_mut()
            .find(|h| h.id == hypothesis)
            .ok_or_else(|| anyhow!("unknown hypothesis"))?;
        let links = if contradicts {
            &mut hypothesis.contradicts
        } else {
            &mut hypothesis.supports
        };
        if !links.contains(&evidence) {
            links.push(evidence);
        }
        hypothesis.status = match (
            hypothesis.supports.is_empty(),
            hypothesis.contradicts.is_empty(),
        ) {
            (false, false) => HypothesisStatus::Unresolved,
            (false, true) => HypothesisStatus::Supported,
            (true, false) => HypothesisStatus::Contradicted,
            (true, true) => HypothesisStatus::Open,
        };
        Ok(())
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock_path = path.with_extension("investigation.lock");
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .context(
                "another client is saving this investigation (or a stale lock needs inspection)",
            )?;
        struct Lock(std::path::PathBuf, Option<std::fs::File>);
        impl Drop for Lock {
            fn drop(&mut self) {
                drop(self.1.take());
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _lock = Lock(lock_path, Some(lock));
        // Refuse to replace an unreadable or foreign ledger. A failed load
        // must never turn into silent loss when the analyst next saves.
        if path.exists() {
            let current = Self::load(path, &self.target_sha256)?;
            if current.disk_revision != self.disk_revision {
                return Err(anyhow!(
                    "investigation changed in another client; reload before saving"
                ));
            }
        } else if self.disk_revision.is_some() {
            return Err(anyhow!(
                "investigation was removed by another client; reload before saving"
            ));
        }
        let encoded = serde_json::to_vec_pretty(self)?;
        if encoded.len() as u64 > MAX_FILE {
            return Err(anyhow!("investigation exceeds 16 MiB"));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension(format!("investigation-{}.tmp", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        use std::io::Write;
        let result = (|| {
            file.write_all(&encoded)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path).context("cannot save investigation")
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        } else {
            self.disk_revision = Some(crate::analysis::hashes::sha256_hex(&encoded));
        }
        result
    }
}

fn check_text(text: &str) -> Result<()> {
    if text.trim().is_empty() || text.len() > MAX_TEXT {
        return Err(anyhow!("text must contain 1–32768 bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::evidence::EvidenceKind;

    #[test]
    fn disk_round_trip_preserves_target_and_refuses_foreign_overwrites() {
        let directory =
            std::env::temp_dir().join(format!("knife-ledger-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("investigation.json");
        let mut ledger = Investigation::new("original");
        ledger
            .ask("Which function validates input?".into())
            .unwrap();
        ledger
            .append(Role::Analyst, "Follow the comparison".into(), vec![])
            .unwrap();
        ledger.save(&path).unwrap();
        assert_eq!(
            Investigation::load(&path, "original")
                .unwrap()
                .messages
                .len(),
            1
        );
        assert!(Investigation::load(&path, "other").is_err());
        assert!(Investigation::new("other").save(&path).is_err());
        let mut stale = Investigation::load(&path, "original").unwrap();
        ledger
            .ask("Which imports feed this function?".into())
            .unwrap();
        ledger.save(&path).unwrap();
        stale.ask("A stale client's question".into()).unwrap();
        assert!(stale
            .save(&path)
            .unwrap_err()
            .to_string()
            .contains("another client"));
        assert_eq!(
            Investigation::load(&path, "original")
                .unwrap()
                .hypotheses
                .len(),
            2
        );
        assert!(!path.with_extension("investigation.lock").exists());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn opposing_evidence_keeps_a_hypothesis_unresolved() {
        let mut ledger = Investigation::new("target");
        let id = ledger.ask("Does this check a password?".into()).unwrap();
        for (summary, contradicts) in [
            ("comparison exists", false),
            ("comparison is unreachable", true),
        ] {
            let record = EvidenceRecord::new(
                "workspace",
                "test",
                EvidenceKind::StaticAnalysis,
                summary,
                vec![],
                vec![],
                vec![],
            );
            let evidence = record.id.clone();
            ledger.record(record).unwrap();
            ledger.link(id, evidence, contradicts).unwrap();
        }
        assert_eq!(ledger.hypotheses[0].status, HypothesisStatus::Unresolved);
        assert!(ledger
            .link(id, EvidenceId("missing".into()), false)
            .is_err());
        let encoded = serde_json::to_vec(&ledger).unwrap();
        let restored: Investigation = serde_json::from_slice(&encoded).unwrap();
        restored.validate().unwrap();
    }
}
