//! Runtime debugger boundary, deliberately separate from static providers.
//! Not advertised until launch, authorization and cleanup are live-verified.
use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Exact workspace authorization, never a generic allow-all boolean.
pub fn validate_authorization(
    workspace_sha256: &str,
    authorized_sha256: Option<&str>,
) -> Result<()> {
    if authorized_sha256 != Some(workspace_sha256) {
        bail!("target execution is disabled; explicit authorization must match the exact workspace SHA-256");
    }
    Ok(())
}

pub fn parse_capture(output: &str) -> Result<Value> {
    let mut records = output
        .lines()
        .filter_map(|line| line.strip_prefix("KNIFE_GDB_JSON:"));
    let raw = records.next().context("GDB capture record missing")?;
    if records.next().is_some() {
        bail!("multiple GDB capture records");
    }
    let report: Value = serde_json::from_str(raw)?;
    if report["schema"].as_u64() != Some(1)
        || report["provider"].as_str() != Some("gdb")
        || report["target_execution"].as_bool() != Some(true)
    {
        bail!("invalid runtime capture schema");
    }
    if report["steps_completed"]
        .as_u64()
        .filter(|steps| *steps <= 128)
        .is_none()
    {
        bail!("invalid runtime step count");
    }
    if let Some(stop) = report.get("stop").filter(|value| !value.is_null()) {
        for key in ["runtime_pc", "runtime_sp"] {
            parse_runtime_address(&stop[key])?;
        }
        parse_runtime_address(&report["runtime_entry"])?;
        if stop["pid"].as_u64().filter(|pid| *pid > 0).is_none() {
            bail!("invalid inferior PID");
        }
        let frames = stop["frames"]
            .as_array()
            .context("runtime frames missing")?;
        if frames.len() > 16 {
            bail!("runtime frame bound exceeded");
        }
        for frame in frames {
            parse_runtime_address(&frame["runtime_pc"])?;
        }
        if let Some(memory) = stop["memory_hex"].as_str() {
            if memory.len() > 128
                || memory.len() % 2 != 0
                || !memory.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                bail!("invalid bounded runtime memory");
            }
        }
    } else if report["error"]
        .as_str()
        .filter(|error| !error.is_empty())
        .is_none()
    {
        bail!("missing runtime stop and failure reason");
    }
    Ok(report)
}

pub fn parse_runtime_address(value: &Value) -> Result<u64> {
    let raw = value
        .as_str()
        .context("runtime address must be hexadecimal text")?;
    Ok(u64::from_str_radix(
        raw.strip_prefix("0x")
            .context("runtime address requires 0x prefix")?,
        16,
    )?)
}

/// Kernel entry relocation plus checked membership in this target's sections.
/// PCs in other modules remain runtime-only, not forced into the target image.
pub fn correlate_pc(
    bin: &crate::model::Binary,
    runtime_entry: u64,
    runtime_pc: u64,
) -> Option<u64> {
    let static_pc = if runtime_pc >= runtime_entry {
        bin.entry.checked_add(runtime_pc - runtime_entry)?
    } else {
        bin.entry.checked_sub(runtime_entry - runtime_pc)?
    };
    let base = crate::analysis::engine::display_base(bin);
    bin.sections
        .iter()
        .any(|section| {
            section.exec
                && base
                    .checked_add(section.vaddr)
                    .and_then(|start| static_pc.checked_sub(start))
                    .is_some_and(|delta| delta < section.vsize)
        })
        .then_some(static_pc)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_is_exact_and_default_denied() {
        assert!(validate_authorization("abc", None).is_err());
        assert!(validate_authorization("abc", Some("all")).is_err());
        assert!(validate_authorization("abc", Some("def")).is_err());
        assert!(validate_authorization("abc", Some("abc")).is_ok());
    }
    #[test]
    fn capture_records_are_typed_and_unique() {
        let record = "KNIFE_GDB_JSON:{\"schema\":1,\"provider\":\"gdb\",\"target_execution\":true,\"steps_completed\":0,\"stop\":null,\"error\":\"denied\"}";
        assert_eq!(parse_capture(record).unwrap()["error"], "denied");
        assert!(parse_capture(&format!("{record}\n{record}")).is_err());
        assert!(parse_capture("KNIFE_GDB_JSON:{}").is_err());
    }
    #[test]
    fn stopped_capture_checks_runtime_addresses_and_bounds() {
        let mut report = serde_json::json!({"schema":1,"provider":"gdb","target_execution":true,"steps_completed":2,"runtime_entry":"0x70001000","stop":{"runtime_pc":"0x70001002","runtime_sp":"0x90000000","pid":123,"frames":[],"memory_hex":"00ff"},"error":null});
        let encode = |value: &Value| format!("KNIFE_GDB_JSON:{value}");
        assert!(parse_capture(&encode(&report)).is_ok());
        report["stop"]["runtime_pc"] = 12.into();
        assert!(parse_capture(&encode(&report)).is_err());
        report["stop"]["runtime_pc"] = "0x70001002".into();
        report["stop"]["memory_hex"] = "x".into();
        assert!(parse_capture(&encode(&report)).is_err());
        report["stop"] = Value::Null;
        assert!(parse_capture(&encode(&report)).is_err());
    }
    #[test]
    fn runtime_pc_requires_target_image_membership() {
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        assert_eq!(correlate_pc(&bin, 0x700001d0, 0x700001d5), Some(0x1d5));
        assert_eq!(correlate_pc(&bin, 0x700001d0, 0x700001c0), Some(0x1c0));
        assert_eq!(correlate_pc(&bin, 0x700001d0, 0x800001d0), None);
        assert_eq!(correlate_pc(&bin, u64::MAX, 0), None);
    }
}
