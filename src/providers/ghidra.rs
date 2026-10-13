//! Validated boundary for Knife's fixed Ghidra exporter.
//! No provider operations are advertised until the process adapter is ready.
use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Extract exactly one exporter record, allowing Ghidra's logging suffix.
/// Target-controlled names cannot impersonate a log record inside JSON.
pub fn parse_export(output: &str) -> Result<Value> {
    let prefix = "KnifeExport.java> KNIFE_GHIDRA_JSON:";
    let mut report = None;
    for line in output.lines() {
        let Some((header, body)) = line.split_once(prefix) else {
            continue;
        };
        if header.trim() != "INFO" {
            continue;
        }
        if report.is_some() {
            bail!("multiple Ghidra exporter records");
        }
        let mut stream = serde_json::Deserializer::from_str(body).into_iter::<Value>();
        let value = stream.next().context("missing Ghidra JSON")??;
        let suffix = body[stream.byte_offset()..].trim();
        if !suffix.is_empty() && suffix != "(GhidraScript)" {
            bail!("unexpected Ghidra exporter suffix");
        }
        if value["schema"].as_u64() != Some(1)
            || value["provider"].as_str() != Some("ghidra")
            || value["analysis_timed_out"].as_bool().is_none()
        {
            bail!("unsupported or incomplete Ghidra exporter record");
        }
        report = Some(value);
    }
    report.context("Ghidra exporter record not found")
}

/// File-backed correlation, not an assumed image-base relocation. An absent
/// source offset or an unmapped byte must remain unknown.
pub fn static_address(session: &crate::workspace::Session, row: &Value) -> Option<u64> {
    correlate(&session.bin, session.bytes.len(), row)
}

fn correlate(bin: &crate::model::Binary, byte_len: usize, row: &Value) -> Option<u64> {
    let offset = row["file_offset"].as_u64()?;
    if offset >= byte_len as u64 {
        return None;
    }
    // Checked arithmetic also rejects malformed section extents.
    let base = crate::analysis::engine::display_base(bin);
    bin.sections.iter().find_map(|section| {
        let delta = offset.checked_sub(section.file_off)?;
        if delta >= section.file_size {
            return None;
        }
        base.checked_add(section.vaddr)?.checked_add(delta)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn correlation_uses_file_bytes_not_provider_base() {
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let mut bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        let section = bin
            .sections
            .iter()
            .find(|s| s.exec && s.file_size > 0)
            .unwrap();
        let offset = section.file_off;
        let expected = section.vaddr;
        let row = serde_json::json!({"address":"0xdeadbeef", "file_offset":offset});
        assert_eq!(correlate(&bin, bytes.len(), &row), Some(expected));
        bin.format = crate::model::Format::Pe;
        bin.image_base = 0x140000000;
        assert_eq!(
            correlate(&bin, bytes.len(), &row),
            Some(0x140000000 + expected)
        );
        assert_eq!(
            correlate(&bin, bytes.len(), &serde_json::json!({"file_offset":null})),
            None
        );
        assert_eq!(
            correlate(
                &bin,
                bytes.len(),
                &serde_json::json!({"file_offset":bytes.len()})
            ),
            None
        );
        bin.image_base = u64::MAX;
        assert_eq!(correlate(&bin, bytes.len(), &row), None);
    }
    #[test]
    fn accepts_logger_suffix_and_preserves_timeout() {
        let value = parse_export("noise\nINFO  KnifeExport.java> KNIFE_GHIDRA_JSON:{\"schema\":1,\"provider\":\"ghidra\",\"analysis_timed_out\":true} (GhidraScript)  \n").unwrap();
        assert_eq!(value["analysis_timed_out"], true);
    }
    #[test]
    fn rejects_duplicate_spoofed_and_incomplete_records() {
        let record = "INFO KnifeExport.java> KNIFE_GHIDRA_JSON:{\"schema\":1,\"provider\":\"ghidra\",\"analysis_timed_out\":false}";
        assert!(parse_export(&format!("{record}\n{record}")).is_err());
        assert!(parse_export(&format!("target {record}")).is_err());
        assert!(parse_export(&format!("{record} garbage")).is_err());
        assert!(parse_export("INFO KnifeExport.java> KNIFE_GHIDRA_JSON:{}").is_err());
    }
}
