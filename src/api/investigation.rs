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
pub struct PlanStep {
    pub id: u64,
    pub text: String,
    pub status: PlanStatus,
    pub evidence: Vec<EvidenceId>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Pending,
    Running,
    Completed,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigation {
    schema: u32,
    pub target_sha256: String,
    pub messages: Vec<Message>,
    pub hypotheses: Vec<Hypothesis>,
    #[serde(default)]
    pub plan: Vec<PlanStep>,
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
            plan: Vec::new(),
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
            || self.plan.len() > MAX_ENTRIES
            || self.hypotheses.len() > MAX_ENTRIES
            || self.evidence.len() > MAX_ENTRIES
        {
            return Err(anyhow!("investigation entry limit reached"));
        }
        for message in &self.messages {
            check_text(&message.text)?;
            self.check_links(&message.evidence)?;
        }
        for step in &self.plan {
            check_text(&step.text)?;
            self.check_links(&step.evidence)?;
            if step.status == PlanStatus::Completed && step.evidence.is_empty() {
                return Err(anyhow!("completed plan steps require supporting evidence"));
            }
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

    pub fn add_plan_step(&mut self, text: String) -> Result<u64> {
        check_text(&text)?;
        if self.plan.len() >= MAX_ENTRIES {
            return Err(anyhow!("plan entry limit reached"));
        }
        let id = self
            .plan
            .iter()
            .map(|step| step.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow!("plan ID exhausted"))?;
        self.plan.push(PlanStep {
            id,
            text,
            status: PlanStatus::Pending,
            evidence: Vec::new(),
        });
        Ok(id)
    }
    pub fn update_plan_step(
        &mut self,
        id: u64,
        status: PlanStatus,
        evidence: Vec<EvidenceId>,
    ) -> Result<()> {
        self.check_links(&evidence)?;
        if status == PlanStatus::Completed && evidence.is_empty() {
            return Err(anyhow!("completed plan steps require supporting evidence"));
        }
        let step = self
            .plan
            .iter_mut()
            .find(|step| step.id == id)
            .ok_or_else(|| anyhow!("unknown plan step"))?;
        step.status = status;
        step.evidence = evidence;
        Ok(())
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

impl Investigation {
    /// Resolve one persisted evidence record by exact ID or unique prefix.
    ///
    /// Prefix matching keeps abbreviated citations usable without trusting a
    /// model to copy a 70-character ID perfectly; an ambiguous prefix is
    /// refused so a shortened ID can never silently select the wrong record.
    /// Writes (linking, recording) still require exact IDs.
    pub fn resolve_evidence(&self, requested: &str) -> Result<&EvidenceRecord> {
        if let Some(record) = self.evidence.get(requested) {
            return Ok(record);
        }
        let matches: Vec<&EvidenceRecord> = self
            .evidence
            .range(requested.to_owned()..)
            .take_while(|(id, _)| id.starts_with(requested))
            .map(|(_, record)| record)
            .collect();
        match matches.as_slice() {
            [record] => Ok(record),
            [] => Err(anyhow!("unknown saved evidence '{requested}'")),
            _ => Err(anyhow!(
                "evidence prefix '{requested}' matches {} records; cite a longer prefix",
                matches.len()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::evidence::EvidenceKind;

    #[test]
    fn evidence_ids_resolve_by_exact_match_or_unique_prefix() {
        let mut ledger = Investigation::new("target");
        for summary in ["first observation", "second observation"] {
            ledger
                .record(crate::api::evidence::EvidenceRecord::new(
                    "target",
                    "triage",
                    EvidenceKind::StaticAnalysis,
                    summary,
                    vec![],
                    vec![],
                    vec![],
                ))
                .unwrap();
        }
        let (first_id, first_summary) = ledger.evidence.iter().next().expect("records are saved");
        assert_eq!(
            ledger.resolve_evidence(first_id).unwrap().summary,
            first_summary.summary
        );
        let prefix = first_id[..12].to_string();
        assert_eq!(
            ledger.resolve_evidence(&prefix).unwrap().summary,
            first_summary.summary
        );
        // A prefix matching several records is refused, never guessed.
        let ambiguous = first_id[..3].to_string();
        let error = ledger.resolve_evidence(&ambiguous).unwrap_err().to_string();
        assert!(error.contains("matches 2 records"), "{error}");
        assert!(ledger.resolve_evidence("ev-ffffffff").is_err());
    }

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
