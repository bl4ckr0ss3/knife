//! Read-only archive inventory for firmware and packaged-artifact workflows.
//!
//! 7-Zip remains an optional, caller-installed parser. Knife invokes one fixed
//! listing command, bounds its output and deadline, and never extracts or runs
//! archive members.

use crate::analysis::hashes;
use crate::api::evidence::{
    Confidence, EvidenceKind, EvidenceRecord, EvidenceStatement, OperationResult, StatementKind,
};
use crate::api::paging::PageWindow;
use crate::providers::process::{executable_identity, find_on_path, run_process, TargetSnapshot};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);
const ROW_LIMIT: usize = 400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub path_risk: Option<String>,
    pub size: Option<u64>,
    pub packed_size: Option<u64>,
    pub directory: bool,
    pub encrypted: Option<bool>,
    pub modified: Option<String>,
    pub attributes: Option<String>,
    pub crc: Option<String>,
    pub method: Option<String>,
    pub block: Option<u64>,
    pub link_kind: Option<String>,
    pub symbolic_link: Option<String>,
    pub hard_link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveInventory {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub archive_type: Option<String>,
    pub physical_size: Option<u64>,
    pub headers_size: Option<u64>,
    pub solid: Option<bool>,
    pub blocks: Option<u64>,
    pub engine_path: String,
    pub engine_identity: String,
    pub matched: usize,
    pub returned: usize,
    pub unsafe_paths: usize,
    pub link_entries: usize,
    pub entries: Vec<ArchiveEntry>,
}

pub fn executable() -> Option<PathBuf> {
    std::env::var_os("KNIFE_7Z")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| find_on_path("7z"))
        .or_else(|| find_on_path("7za"))
}

pub fn inspect(args: &Value) -> Result<Value> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing `path`"))?;
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(anyhow!("artifact path must be absolute"));
    }
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("cannot inspect artifact {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("artifact path must name a regular file"));
    }
    let bytes =
        std::fs::read(path).with_context(|| format!("cannot read artifact {}", path.display()))?;
    let sha256 = hashes::sha256_hex(&bytes);
    // Inventory the exact bytes identified above. Passing the caller's path to
    // 7-Zip would let a concurrent replacement produce metadata for a different
    // object than the evidence digest.
    let snapshot = TargetSnapshot::create("artifact", &bytes)?;
    let executable = executable().ok_or_else(|| {
        anyhow!("7-Zip is not installed or not on PATH; install it or set KNIFE_7Z")
    })?;
    let output = run_process(
        &executable,
        [
            OsString::from("l"),
            OsString::from("-slt"),
            OsString::from("--"),
            snapshot.path().as_os_str().to_owned(),
        ],
        DEADLINE,
        OUTPUT_LIMIT,
    )?;
    if output.truncated {
        return Err(anyhow!("7-Zip listing exceeded the 16 MiB output bound"));
    }
    if !output.status.success() {
        return Err(anyhow!(
            "7-Zip could not inventory the artifact: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let parsed = parse_slt(&String::from_utf8_lossy(&output.stdout))?;
    let scope = format!("artifact_inventory:{sha256}");
    let page = PageWindow::from_args(args, parsed.entries.len(), 100, ROW_LIMIT, &scope)?;
    let entries = parsed
        .entries
        .iter()
        .skip(page.offset)
        .take(page.limit)
        .cloned()
        .collect::<Vec<_>>();
    let unsafe_paths = parsed
        .entries
        .iter()
        .filter(|entry| entry.path_risk.is_some())
        .count();
    let link_entries = parsed
        .entries
        .iter()
        .filter(|entry| entry.link_kind.is_some())
        .count();
    let data = ArchiveInventory {
        path: path.to_string_lossy().into_owned(),
        sha256: sha256.clone(),
        size: bytes.len() as u64,
        archive_type: parsed.archive_type,
        physical_size: parsed.physical_size,
        headers_size: parsed.headers_size,
        solid: parsed.solid,
        blocks: parsed.blocks,
        engine_path: executable.to_string_lossy().into_owned(),
        engine_identity: executable_identity(&executable),
        matched: page.total,
        returned: entries.len(),
        unsafe_paths,
        link_entries,
        entries,
    };
    let evidence = EvidenceRecord::new(
        sha256,
        "artifact_inventory",
        EvidenceKind::StaticAnalysis,
        format!("7-Zip listed {} archive entries", page.total),
        vec![],
        vec![EvidenceStatement {
            kind: StatementKind::Observation,
            text: "A bounded external 7-Zip listing reported archive metadata and member records."
                .into(),
            confidence: Confidence::Certain,
        }],
        vec![
            "The target was read and listed but not extracted or executed.".into(),
            "Member sizes, encryption flags, CRC values and methods are provider-reported; member byte ranges and content digests are not established by this operation.".into(),
            "Paths are decoded from the provider's textual output; undecodable filesystem names may be represented lossily.".into(),
            "Path-risk labels are syntactic. The extractor's normalization and link-handling behavior must be validated separately for exploitability.".into(),
        ],
    );
    let result = OperationResult {
        contract_version: crate::api::evidence::EVIDENCE_CONTRACT_VERSION,
        data,
        evidence: vec![evidence],
        partial: page.next_cursor.is_some(),
        continuation: page.next_cursor,
    };
    serde_json::to_value(result).map_err(Into::into)
}

#[derive(Default)]
struct ParsedListing {
    archive_type: Option<String>,
    physical_size: Option<u64>,
    headers_size: Option<u64>,
    solid: Option<bool>,
    blocks: Option<u64>,
    entries: Vec<ArchiveEntry>,
}

fn parse_slt(output: &str) -> Result<ParsedListing> {
    let mut parsed = ParsedListing::default();
    let (header, members) = output
        .split_once("----------")
        .ok_or_else(|| anyhow!("7-Zip listing did not contain a member boundary"))?;
    for line in header.lines() {
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        match key.trim() {
            "Type" => parsed.archive_type = Some(value.trim().to_string()),
            "Physical Size" => parsed.physical_size = value.trim().parse().ok(),
            "Headers Size" => parsed.headers_size = value.trim().parse().ok(),
            "Solid" => parsed.solid = parse_bool(value),
            "Blocks" => parsed.blocks = value.trim().parse().ok(),
            _ => {}
        }
    }
    for record in members.split("\n\n") {
        let mut fields = std::collections::BTreeMap::new();
        for line in record.lines() {
            if let Some((key, value)) = line.split_once(" = ") {
                fields.insert(key.trim(), value.trim());
            }
        }
        let Some(path) = fields.get("Path").filter(|value| !value.is_empty()) else {
            continue;
        };
        let attributes = fields.get("Attributes").map(|value| (*value).to_string());
        let symbolic_link = text_field(&fields, "Symbolic Link");
        let hard_link = text_field(&fields, "Hard Link");
        let link_kind = if symbolic_link.is_some()
            || attributes
                .as_deref()
                .is_some_and(|value| value.split_whitespace().any(|word| word.starts_with('l')))
        {
            Some("symbolic".into())
        } else if hard_link.is_some() {
            Some("hard".into())
        } else {
            None
        };
        let directory = fields
            .get("Folder")
            .and_then(|value| parse_bool(value))
            .unwrap_or(false)
            || attributes
                .as_deref()
                .is_some_and(|value| value.contains('D'));
        parsed.entries.push(ArchiveEntry {
            path: (*path).to_string(),
            path_risk: path_risk(path),
            size: fields.get("Size").and_then(|value| value.parse().ok()),
            packed_size: fields
                .get("Packed Size")
                .and_then(|value| value.parse().ok()),
            directory,
            encrypted: fields.get("Encrypted").and_then(|value| parse_bool(value)),
            modified: text_field(&fields, "Modified"),
            attributes,
            crc: text_field(&fields, "CRC"),
            method: text_field(&fields, "Method"),
            block: fields.get("Block").and_then(|value| value.parse().ok()),
            link_kind,
            symbolic_link,
            hard_link,
        });
    }
    if parsed.entries.is_empty() {
        return Err(anyhow!("7-Zip reported no archive members"));
    }
    Ok(parsed)
}

fn path_risk(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let bytes = normalized.as_bytes();
    if normalized.starts_with('/')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        return Some("absolute".into());
    }
    normalized
        .split('/')
        .any(|component| component == "..")
        .then(|| "parent_traversal".into())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim() {
        "+" => Some(true),
        "-" => Some(false),
        _ => None,
    }
}

fn text_field(fields: &std::collections::BTreeMap<&str, &str>, key: &str) -> Option<String> {
    fields
        .get(key)
        .filter(|value| !value.is_empty())
        .map(|value| (*value).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_archive_header_and_member_security_fields() {
        let parsed = parse_slt(
            "Type = 7z\nPhysical Size = 99\nHeaders Size = 12\nSolid = +\nBlocks = 1\n\n----------\nPath = cert.ssl\nSize = 344\nPacked Size = 88\nEncrypted = -\nMethod = LZMA2:25\nBlock = 0\n\nPath = bin\nSize = 0\nFolder = +\nAttributes = D\nEncrypted = -\n\nPath = ../escape\nSize = 1\nAttributes = A lrwxrwxrwx\nSymbolic Link = /tmp/target\n",
        )
        .unwrap();
        assert_eq!(parsed.archive_type.as_deref(), Some("7z"));
        assert_eq!(parsed.physical_size, Some(99));
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].path, "cert.ssl");
        assert_eq!(parsed.entries[0].encrypted, Some(false));
        assert!(parsed.entries[1].directory);
        assert_eq!(
            parsed.entries[2].path_risk.as_deref(),
            Some("parent_traversal")
        );
        assert_eq!(
            parsed.entries[2].symbolic_link.as_deref(),
            Some("/tmp/target")
        );
        assert_eq!(parsed.entries[2].link_kind.as_deref(), Some("symbolic"));
        assert_eq!(path_risk("C:\\temp\\payload"), Some("absolute".into()));
    }
}
