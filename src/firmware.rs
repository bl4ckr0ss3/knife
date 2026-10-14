//! Strict, read-only parsers for firmware container formats.

use crate::analysis::hashes;
use crate::api::evidence::{
    Confidence, EvidenceKind, EvidenceRecord, EvidenceStatement, OperationResult, StatementKind,
};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

const INPUT_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRegion {
    pub start: String,
    pub end_exclusive: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelHexInventory {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub records: usize,
    pub data_records: usize,
    pub data_bytes: usize,
    pub data_sha256_in_record_order: String,
    pub eof_present: bool,
    pub address_min: Option<String>,
    pub address_max_exclusive: Option<String>,
    pub regions: Vec<AddressRegion>,
    pub overlapping_data_records: usize,
    pub start_linear_address: Option<String>,
    pub start_segment_address: Option<String>,
}

pub fn inspect_intel_hex(args: &Value) -> Result<Value> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing `path`"))?;
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(anyhow!("firmware path must be absolute"));
    }
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("cannot inspect firmware {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("firmware path must name a regular file"));
    }
    if metadata.len() > INPUT_LIMIT {
        return Err(anyhow!("Intel HEX input exceeds the 64 MiB bound"));
    }
    let bytes =
        std::fs::read(path).with_context(|| format!("cannot read firmware {}", path.display()))?;
    let target_sha256 = hashes::sha256_hex(&bytes);
    let parsed = parse_intel_hex(&bytes)?;
    let data = IntelHexInventory {
        path: path.to_string_lossy().into_owned(),
        sha256: target_sha256.clone(),
        size: metadata.len(),
        records: parsed.records,
        data_records: parsed.intervals.len(),
        data_bytes: parsed.payload.len(),
        data_sha256_in_record_order: hashes::sha256_hex(&parsed.payload),
        eof_present: parsed.eof_present,
        address_min: parsed
            .intervals
            .iter()
            .map(|(start, _)| *start)
            .min()
            .map(hex32),
        address_max_exclusive: parsed
            .intervals
            .iter()
            .map(|(_, end)| *end)
            .max()
            .map(hex32),
        regions: merge_regions(&parsed.intervals),
        overlapping_data_records: count_overlaps(&parsed.intervals),
        start_linear_address: parsed.start_linear.map(hex32),
        start_segment_address: parsed.start_segment.map(hex32),
    };
    let evidence = EvidenceRecord::new(
        target_sha256,
        "intel_hex_inventory",
        EvidenceKind::StaticAnalysis,
        format!(
            "Validated {} Intel HEX records containing {} data bytes",
            data.records, data.data_bytes
        ),
        vec![],
        vec![EvidenceStatement {
            kind: StatementKind::Observation,
            text: "Every parsed Intel HEX record passed its encoded length and checksum checks."
                .into(),
            confidence: Confidence::Certain,
        }],
        vec![
            "Addresses describe the Intel HEX load map; they do not identify the target CPU or prove runtime behavior.".into(),
            "The data digest concatenates data records in file order and does not fill address gaps.".into(),
        ],
    );
    serde_json::to_value(OperationResult {
        contract_version: crate::api::evidence::EVIDENCE_CONTRACT_VERSION,
        data,
        evidence: vec![evidence],
        partial: false,
        continuation: None,
    })
    .map_err(Into::into)
}

#[derive(Debug, Default)]
struct ParsedHex {
    records: usize,
    eof_present: bool,
    payload: Vec<u8>,
    intervals: Vec<(u32, u32)>,
    start_linear: Option<u32>,
    start_segment: Option<u32>,
}

fn parse_intel_hex(input: &[u8]) -> Result<ParsedHex> {
    let text = std::str::from_utf8(input).context("Intel HEX must be ASCII/UTF-8 text")?;
    let mut parsed = ParsedHex::default();
    let mut base = 0u32;
    for (index, raw_line) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if parsed.eof_present {
            return Err(anyhow!("line {line_no}: record follows the EOF record"));
        }
        let encoded = line
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("line {line_no}: missing ':' prefix"))?;
        if encoded.len() < 10 || encoded.len() % 2 != 0 {
            return Err(anyhow!("line {line_no}: malformed encoded record length"));
        }
        let mut record = Vec::with_capacity(encoded.len() / 2);
        for offset in (0..encoded.len()).step_by(2) {
            record.push(
                u8::from_str_radix(&encoded[offset..offset + 2], 16).map_err(|_| {
                    anyhow!(
                        "line {line_no}: invalid hexadecimal byte at column {}",
                        offset + 2
                    )
                })?,
            );
        }
        let length = record[0] as usize;
        if record.len() != length + 5 {
            return Err(anyhow!(
                "line {line_no}: byte count does not match record length"
            ));
        }
        if record.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
            return Err(anyhow!("line {line_no}: checksum mismatch"));
        }
        let address = u16::from_be_bytes([record[1], record[2]]) as u32;
        let kind = record[3];
        let data = &record[4..4 + length];
        match kind {
            0x00 => {
                let start = base
                    .checked_add(address)
                    .ok_or_else(|| anyhow!("line {line_no}: data address overflow"))?;
                let end = start
                    .checked_add(length as u32)
                    .ok_or_else(|| anyhow!("line {line_no}: data range overflow"))?;
                parsed.payload.extend_from_slice(data);
                parsed.intervals.push((start, end));
            }
            0x01 if length == 0 && address == 0 => parsed.eof_present = true,
            0x02 if length == 2 && address == 0 => {
                base = (u16::from_be_bytes([data[0], data[1]]) as u32) << 4;
            }
            0x03 if length == 4 && address == 0 => {
                let cs = u16::from_be_bytes([data[0], data[1]]) as u32;
                let ip = u16::from_be_bytes([data[2], data[3]]) as u32;
                parsed.start_segment = Some((cs << 4).saturating_add(ip));
            }
            0x04 if length == 2 && address == 0 => {
                base = (u16::from_be_bytes([data[0], data[1]]) as u32) << 16;
            }
            0x05 if length == 4 && address == 0 => {
                parsed.start_linear =
                    Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
            0x01..=0x05 => {
                return Err(anyhow!(
                    "line {line_no}: invalid fields for record type {kind:02x}"
                ))
            }
            _ => {
                return Err(anyhow!(
                    "line {line_no}: unsupported record type {kind:02x}"
                ))
            }
        }
        parsed.records += 1;
    }
    if parsed.records == 0 {
        return Err(anyhow!("Intel HEX input contains no records"));
    }
    if !parsed.eof_present {
        return Err(anyhow!("Intel HEX input has no EOF record"));
    }
    Ok(parsed)
}

fn merge_regions(intervals: &[(u32, u32)]) -> Vec<AddressRegion> {
    let mut sorted = intervals.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::new();
    for (start, end) in sorted {
        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
        .into_iter()
        .map(|(start, end)| AddressRegion {
            start: hex32(start),
            end_exclusive: hex32(end),
        })
        .collect()
}

fn count_overlaps(intervals: &[(u32, u32)]) -> usize {
    let mut sorted = intervals.to_vec();
    sorted.sort_unstable();
    let mut furthest = 0u32;
    let mut overlaps = 0usize;
    for (index, (start, end)) in sorted.into_iter().enumerate() {
        if index > 0 && start < furthest {
            overlaps += 1;
        }
        furthest = furthest.max(end);
    }
    overlaps
}

fn hex32(value: u32) -> String {
    format!("0x{value:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_extended_linear_map_and_entry() {
        let parsed = parse_intel_hex(
            b":020000040800F2\n:0400100001020304E2\n:0400000508000010DF\n:00000001FF\n",
        )
        .unwrap();
        assert_eq!(parsed.intervals, vec![(0x0800_0010, 0x0800_0014)]);
        assert_eq!(parsed.start_linear, Some(0x0800_0010));
        assert!(parsed.eof_present);
    }

    #[test]
    fn rejects_checksum_mismatch() {
        let error = parse_intel_hex(b":0400100001020304E3\n:00000001FF\n").unwrap_err();
        assert!(error.to_string().contains("checksum mismatch"));
    }
}
