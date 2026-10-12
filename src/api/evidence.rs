//! Stable evidence records returned by agent-facing operations.
//!
//! Front ends should be able to explain where a conclusion came from without
//! parsing rendered prose.  These types deliberately separate direct
//! observations from inferences and unresolved unknowns.

use crate::address::{FileOffset, RuntimeVa, StaticVa};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EVIDENCE_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    TargetIdentity,
    StaticAnalysis,
    RuntimeObservation,
    AnalystFact,
    Comparison,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementKind {
    Observation,
    Inference,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Certain,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_address: Option<StaticVa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_address: Option<RuntimeVa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<FileOffset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStatement {
    pub kind: StatementKind,
    pub text: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub target_sha256: String,
    pub producer: String,
    pub kind: EvidenceKind,
    pub summary: String,
    pub locations: Vec<EvidenceLocation>,
    pub statements: Vec<EvidenceStatement>,
    pub limitations: Vec<String>,
}

impl EvidenceRecord {
    /// Construct a record with an ID stable across identical analyses.
    pub fn new(
        target_sha256: impl Into<String>,
        producer: impl Into<String>,
        kind: EvidenceKind,
        summary: impl Into<String>,
        locations: Vec<EvidenceLocation>,
        statements: Vec<EvidenceStatement>,
        limitations: Vec<String>,
    ) -> Self {
        let target_sha256 = target_sha256.into();
        let producer = producer.into();
        let summary = summary.into();
        let mut digest = Sha256::new();
        digest.update(EVIDENCE_CONTRACT_VERSION.to_le_bytes());
        digest.update(target_sha256.as_bytes());
        digest.update(producer.as_bytes());
        digest.update(format!("{kind:?}").as_bytes());
        digest.update(summary.as_bytes());
        digest.update(serde_json::to_vec(&locations).unwrap_or_default());
        digest.update(serde_json::to_vec(&statements).unwrap_or_default());
        digest.update(serde_json::to_vec(&limitations).unwrap_or_default());
        let id = format!("ev-{:x}", digest.finalize());
        Self {
            id: EvidenceId(id),
            target_sha256,
            producer,
            kind,
            summary,
            locations,
            statements,
            limitations,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationResult<T> {
    pub contract_version: u32,
    pub data: T,
    pub evidence: Vec<EvidenceRecord>,
    pub partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<String>,
}

impl<T> OperationResult<T> {
    pub fn complete(data: T, evidence: Vec<EvidenceRecord>) -> Self {
        Self {
            contract_version: EVIDENCE_CONTRACT_VERSION,
            data,
            evidence,
            partial: false,
            continuation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_ids_are_stable_and_content_addressed() {
        let make = |summary: &str, limitations: Vec<String>| {
            EvidenceRecord::new(
                "deadbeef",
                "test",
                EvidenceKind::StaticAnalysis,
                summary,
                vec![EvidenceLocation {
                    static_address: Some(StaticVa(0x401000)),
                    ..EvidenceLocation::default()
                }],
                vec![],
                limitations,
            )
        };
        assert_eq!(
            make("entry point", vec![]).id,
            make("entry point", vec![]).id
        );
        assert_ne!(make("entry point", vec![]).id, make("different", vec![]).id);
        assert_ne!(
            make("entry point", vec![]).id,
            make("entry point", vec!["bounded search".into()]).id
        );
    }

    #[test]
    fn result_serializes_the_contract_version_and_evidence() {
        let result = OperationResult::complete(serde_json::json!({"ok": true}), vec![]);
        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value["contract_version"], EVIDENCE_CONTRACT_VERSION);
        assert_eq!(value["partial"], false);
        assert!(value.get("continuation").is_none());
    }
}
