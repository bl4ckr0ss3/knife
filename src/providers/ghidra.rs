//! Validated boundary for Knife's fixed Ghidra exporter.
//! Fixed process requests, bounded cached reports and typed file correlation.
use super::process::{executable_identity, JsonCache};
use crate::api::operations::{OperationDescriptor, ResultMode};
use crate::workspace::Session;
use anyhow::{bail, Context, Result};
use serde_json::json;
use serde_json::Value;
use std::sync::{Mutex, OnceLock};
use std::{ffi::OsString, path::PathBuf, time::Duration};
static CACHE: OnceLock<Mutex<JsonCache>> = OnceLock::new();

pub fn executable() -> Option<PathBuf> {
    std::env::var_os("KNIFE_GHIDRA_HEADLESS")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

pub fn status() -> super::ProviderStatus {
    let path = executable();
    super::ProviderStatus {
        id: "ghidra", name: "Ghidra", installed: path.is_some(),
        executable: path.map(|p| p.display().to_string()), version: None,
        mode: "out_of_process_static", target_execution: false,
        license: "Apache-2.0; separately installed executable",
        operations: vec!["ghidra_functions", "ghidra_decompile"],
        limitation: Some("Requires JDK and KNIFE_GHIDRA_WORK_ROOT; inventory capped at 20,000 functions; engine version not probed".into()),
    }
}

pub fn catalog() -> Vec<OperationDescriptor> {
    vec![
        OperationDescriptor::read("ghidra_functions", "Independent Ghidra static function inventory; preserves provider addresses and maps file-backed entry points to Knife locations.", json!({"limit":{"type":"integer","minimum":1,"maximum":400},"cursor":{"type":"string"},"timeout_seconds":{"type":"integer","minimum":10,"maximum":300}}), &[]).with_result_mode(ResultMode::Paginated).with_evidence(),
        OperationDescriptor::read("ghidra_decompile", "Ghidra pseudocode at a Ghidra provider static address, not a Knife or runtime address. Results are inferred, not execution evidence.", json!({"provider_static_address":{"type":"string"},"timeout_seconds":{"type":"integer","minimum":10,"maximum":300}}), &["provider_static_address"]).with_evidence(),
    ]
}

pub fn dispatch(session: &Session, name: &str, args: &Value) -> Result<Value> {
    if !matches!(
        session.bin.format,
        crate::model::Format::Pe | crate::model::Format::Elf
    ) {
        bail!("Ghidra initial adapter supports PE and ELF only");
    }
    let timeout = args
        .get("timeout_seconds")
        .map(|v| {
            v.as_u64()
                .filter(|n| (10..=300).contains(n))
                .context("timeout_seconds must be an integer between 10 and 300")
        })
        .transpose()?
        .unwrap_or(90);
    if let Some(limit) = args.get("limit") {
        if !limit.as_u64().is_some_and(|n| (1..=400).contains(&n)) {
            bail!("limit must be an integer between 1 and 400");
        }
    }
    let request = match name {
        "ghidra_functions" => ExportRequest::Functions { limit: 20000 },
        "ghidra_decompile" => {
            let raw = args["provider_static_address"]
                .as_str()
                .context("missing provider_static_address")?;
            let address = u64::from_str_radix(
                raw.strip_prefix("0x")
                    .context("provider_static_address requires 0x hexadecimal")?,
                16,
            )?;
            ExportRequest::Decompile {
                provider_static_address: address,
            }
        }
        _ => bail!("unknown Ghidra operation"),
    };
    let executable = executable().context("Ghidra unavailable; configure KNIFE_GHIDRA_HEADLESS")?;
    let workspace = crate::analysis::hashes::sha256_hex(&session.bytes);
    let key = format!(
        "{workspace}:{timeout}:{}:{}:{}:{}",
        executable_identity(&executable),
        crate::analysis::hashes::sha256_hex(include_bytes!("ghidra/KnifeExport.java")),
        name,
        args["provider_static_address"]
    );
    let cache = CACHE.get_or_init(|| Mutex::new(JsonCache::new(8, 32 * 1024 * 1024)));
    let cached = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("Ghidra cache poisoned"))?
        .get(&key);
    let raw = match cached {
        Some(report) => report,
        None => {
            if args.get("cursor").is_some() {
                bail!("Ghidra continuation report expired; restart pagination");
            }
            let report = export(&session.bytes, request, timeout)?;
            cache
                .lock()
                .map_err(|_| anyhow::anyhow!("Ghidra cache poisoned"))?
                .insert(key, report.clone());
            report
        }
    };
    shape(session, name, args, &raw)
}

fn shape(session: &Session, name: &str, args: &Value, raw: &Value) -> Result<Value> {
    let digest = crate::analysis::hashes::sha256_hex(&serde_json::to_vec(raw)?);
    let mut data = raw.clone();
    data["result_sha256"] = digest.clone().into();
    let mut partial = raw["analysis_timed_out"].as_bool().unwrap_or(true);
    if name == "ghidra_functions" {
        let rows = raw["functions"]
            .as_array()
            .context("Ghidra inventory missing")?;
        let page = crate::api::paging::PageWindow::from_args(
            args,
            rows.len(),
            100,
            400,
            &format!("ghidra-functions:{digest}"),
        )?;
        let mut selected = rows
            .iter()
            .skip(page.offset)
            .take(page.limit)
            .cloned()
            .collect::<Vec<_>>();
        for row in &mut selected {
            row["knife_static_address"] = static_address(session, row)
                .map(|a| json!(format!("0x{a:x}")))
                .unwrap_or(Value::Null);
        }
        data["functions"] = selected.into();
        data["available_rows"] = rows.len().into();
        data["next_cursor"] = serde_json::to_value(&page.next_cursor)?;
        data["page"] = serde_json::to_value(page)?;
        partial |= raw["truncated"].as_bool().unwrap_or(true);
    } else {
        let row = data
            .get_mut("function")
            .context("Ghidra function missing")?;
        row["knife_static_address"] = static_address(session, row)
            .map(|a| json!(format!("0x{a:x}")))
            .unwrap_or(Value::Null);
        partial |= raw["decompile_completed"].as_bool() != Some(true)
            || raw["pseudocode_truncated"].as_bool().unwrap_or(false);
    }
    data["partial"] = partial.into();
    Ok(data)
}

pub fn evidence_locations(
    session: &Session,
    data: &Value,
) -> Vec<crate::api::evidence::EvidenceLocation> {
    let rows: Vec<&Value> = data["functions"]
        .as_array()
        .map(|r| r.iter().collect())
        .unwrap_or_else(|| data.get("function").into_iter().collect());
    rows.into_iter()
        .take(400)
        .map(|row| crate::api::evidence::EvidenceLocation {
            static_address: static_address(session, row).map(crate::address::StaticVa),
            runtime_address: None,
            file_offset: row["file_offset"]
                .as_u64()
                .filter(|n| *n < session.bytes.len() as u64)
                .map(crate::address::FileOffset),
            symbol: row["name"].as_str().map(str::to_owned),
        })
        .collect()
}

/// Fixed exporter modes; callers cannot supply arbitrary scripts or switches.
pub enum ExportRequest {
    Functions { limit: u16 },
    Decompile { provider_static_address: u64 },
}

struct ProjectDirectory(PathBuf);
impl Drop for ProjectDirectory {
    fn drop(&mut self) {
        // Only a directory exclusively created by this invocation is owned.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Execute static analysis of exact workspace bytes in an isolated project.
/// The configured root must be disk-backed and contain no hidden components.
pub fn export(bytes: &[u8], request: ExportRequest, timeout_seconds: u64) -> Result<Value> {
    use super::process::run_process_with_env;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    if !(10..=300).contains(&timeout_seconds) {
        bail!("Ghidra timeout must be 10–300 seconds");
    }
    let mode: Vec<OsString> = match request {
        ExportRequest::Functions { limit } if (1..=20000).contains(&limit) => {
            vec!["functions".into(), limit.to_string().into()]
        }
        ExportRequest::Functions { .. } => bail!("Ghidra export limit must be 1–20000"),
        ExportRequest::Decompile {
            provider_static_address,
        } => vec![
            "decompile".into(),
            format!("0x{provider_static_address:x}").into(),
        ],
    };
    let executable = PathBuf::from(
        std::env::var_os("KNIFE_GHIDRA_HEADLESS")
            .context("set KNIFE_GHIDRA_HEADLESS to analyzeHeadless")?,
    );
    if !executable.is_file() {
        bail!("Ghidra headless executable not found");
    }
    let root = PathBuf::from(
        std::env::var_os("KNIFE_GHIDRA_WORK_ROOT")
            .context("set KNIFE_GHIDRA_WORK_ROOT to a disk-backed project root")?,
    )
    .canonicalize()?;
    if !root.is_dir()
        || root
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
    {
        bail!("Ghidra project root must be a directory without hidden path components");
    }
    let mut allocated = None;
    for _ in 0..32 {
        let directory = root.join(format!(
            "knife-ghidra-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&directory) {
            Ok(()) => {
                allocated = Some(ProjectDirectory(directory));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let project = allocated.context("cannot allocate private Ghidra project")?;
    let scripts = project.0.join("scripts");
    std::fs::create_dir(&scripts)?;
    std::fs::write(
        scripts.join("KnifeExport.java"),
        include_str!("ghidra/KnifeExport.java"),
    )?;
    // Keep the input disk-backed too: temp_dir may be a small tmpfs.
    let snapshot = project.0.join("target.bin");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&snapshot)?;
    file.write_all(bytes)?;
    file.flush()?;
    drop(file);
    let mut args = vec![
        project.0.as_os_str().to_owned(),
        "analysis".into(),
        "-import".into(),
        snapshot.as_os_str().to_owned(),
        "-readOnly".into(),
        "-analysisTimeoutPerFile".into(),
        timeout_seconds.saturating_sub(5).to_string().into(),
        "-max-cpu".into(),
        "1".into(),
        "-scriptPath".into(),
        scripts.as_os_str().to_owned(),
        "-postScript".into(),
        "KnifeExport.java".into(),
    ];
    args.extend(mode);
    let output = run_process_with_env(
        &executable,
        args,
        Duration::from_secs(timeout_seconds),
        8 * 1024 * 1024,
        &[("GHIDRA_HEADLESS_MAXMEM", "512M")],
    )?;
    if !output.status.success() || output.truncated {
        bail!(
            "Ghidra failed or exceeded output limit: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(2000)
                .collect::<String>()
        );
    }
    let mut report =
        parse_export(std::str::from_utf8(&output.stdout).context("Ghidra output is not UTF-8")?)?;
    let workspace_sha256 = crate::analysis::hashes::sha256_hex(bytes);
    if report["sample_sha256"].as_str() != Some(workspace_sha256.as_str()) {
        bail!("Ghidra imported sample identity does not match workspace bytes");
    }
    report["workspace_sha256"] = workspace_sha256.into();
    report["target_execution"] = false.into();
    Ok(report)
}

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
    // Overlay/non-memory spaces can reuse source bytes at distinct locations.
    // The initial native provider only correlates its ordinary RAM space.
    if row["address_space"].as_str() != Some("ram") {
        return None;
    }
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
    fn fixture_session() -> Session {
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        let an = crate::analysis::engine::Analysis::empty(bin.arch);
        Session {
            bin,
            bytes,
            an,
            db: crate::db::Db::default(),
            code_analyzed: false,
        }
    }
    #[test]
    fn inventory_pages_are_report_scoped_and_timeouts_remain_partial() {
        let session = fixture_session();
        let raw = json!({"analysis_timed_out":true,"truncated":false,"total":3,"functions":[{"name":"a","file_offset":null},{"name":"b","file_offset":null},{"name":"c","file_offset":null}]});
        let first = shape(&session, "ghidra_functions", &json!({"limit":1}), &raw).unwrap();
        assert_eq!(first["functions"][0]["name"], "a");
        assert_eq!(first["partial"], true);
        assert_eq!(first["functions"][0]["knife_static_address"], Value::Null);
        let next = json!({"limit":1,"cursor":first["next_cursor"]});
        let second = shape(&session, "ghidra_functions", &next, &raw).unwrap();
        assert_eq!(second["functions"][0]["name"], "b");
        let mut changed = raw.clone();
        changed["total"] = 4.into();
        assert!(shape(&session, "ghidra_functions", &next, &changed).is_err());
    }
    #[test]
    fn failed_decompilation_never_becomes_complete() {
        let session = fixture_session();
        let raw = json!({"analysis_timed_out":false,"function":{"name":"unknown","file_offset":null},"decompile_completed":false,"error":"failed"});
        let data = shape(&session, "ghidra_decompile", &json!({}), &raw).unwrap();
        assert_eq!(data["partial"], true);
        assert_eq!(data["error"], "failed");
        assert_eq!(evidence_locations(&session, &data)[0].static_address, None);
    }
    #[test]
    #[ignore = "requires a configured Ghidra installation, JDK, project root and test target"]
    fn live_isolated_function_export() {
        let target = std::env::var("KNIFE_GHIDRA_TEST_TARGET").expect("set test target");
        let bytes = std::fs::read(target).unwrap();
        let report = export(&bytes, ExportRequest::Functions { limit: 2 }, 90).unwrap();
        assert_eq!(
            report["workspace_sha256"],
            crate::analysis::hashes::sha256_hex(&bytes)
        );
        assert_eq!(report["target_execution"], false);
        assert!(report["functions"].as_array().unwrap().len() <= 2);
        assert!(report["total"].as_u64().unwrap() > 0);
        assert!(report["functions"][0]["file_offset"].as_u64().unwrap() < bytes.len() as u64);
    }
    #[test]
    fn rejects_invalid_export_requests_before_launch() {
        assert!(export(&[], ExportRequest::Functions { limit: 0 }, 30).is_err());
        assert!(export(&[], ExportRequest::Functions { limit: 20001 }, 30).is_err());
        assert!(export(&[], ExportRequest::Functions { limit: 2 }, 301).is_err());
    }
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
        let row = serde_json::json!({"address":"0xdeadbeef", "address_space":"ram", "file_offset":offset});
        assert_eq!(correlate(&bin, bytes.len(), &row), Some(expected));
        let mut overlay = row.clone();
        overlay["address_space"] = "overlay".into();
        assert_eq!(correlate(&bin, bytes.len(), &overlay), None);
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
