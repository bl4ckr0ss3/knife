//! Fixed-command adapter for standalone capa capability analysis.
use super::process::{executable_identity, find_on_path, run_process, JsonCache, TargetSnapshot};
use super::ProviderStatus;
use crate::address::{FileOffset, StaticVa};
use crate::api::evidence::EvidenceLocation;
use crate::api::{operations::OperationDescriptor, operations::ResultMode, paging::PageWindow};
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};
use std::{ffi::OsString, path::PathBuf, time::Duration};
static CACHE: OnceLock<Mutex<JsonCache>> = OnceLock::new();

pub fn executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("KNIFE_CAPA") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    find_on_path("capa")
}
pub fn status() -> ProviderStatus {
    let executable = executable();
    let version = executable
        .as_ref()
        .and_then(|path| {
            run_process(
                path,
                [OsString::from("--version")],
                Duration::from_secs(3),
                4096,
            )
            .ok()
        })
        .filter(|result| result.status.success() && !result.truncated)
        .map(|result| String::from_utf8_lossy(&result.stdout).trim().to_string());
    ProviderStatus {
        id: "capa",
        name: "capa",
        installed: executable.is_some(),
        executable: executable.as_ref().map(|path| path.display().to_string()),
        version,
        mode: "out_of_process_static",
        target_execution: false,
        license: "Apache-2.0; separately installed executable",
        operations: vec!["capa_capabilities", "capa_rule_matches"],
        limitation: executable
            .is_none()
            .then(|| "Install standalone capa or set KNIFE_CAPA to its executable".into()),
    }
}
pub fn descriptor() -> OperationDescriptor {
    OperationDescriptor::read("capa_capabilities","Independent capa capability rules, ATT&CK/MBC metadata and typed match locations from static workspace bytes.",json!({"limit":{"type":"integer","minimum":1,"maximum":400},"timeout_seconds":{"type":"integer","minimum":1,"maximum":120},"cursor":{"type":"string"}}),&[]).with_result_mode(ResultMode::Paginated).with_evidence()
}
pub fn matches_descriptor() -> OperationDescriptor {
    OperationDescriptor::read("capa_rule_matches","Inspect a matched capa rule's source and bounded supporting match trees, preserving typed locations.",json!({"rule":{"type":"string","maxLength":256},"limit":{"type":"integer","minimum":1,"maximum":20},"cursor":{"type":"string"},"timeout_seconds":{"type":"integer","minimum":1,"maximum":120}}),&["rule"]).with_result_mode(ResultMode::Paginated).with_evidence()
}
pub fn dispatch(session: &Session, args: &Value) -> Result<Value> {
    let timeout = args
        .get("timeout_seconds")
        .map(|value| {
            value
                .as_u64()
                .filter(|value| (1..=120).contains(value))
                .ok_or_else(|| anyhow!("timeout_seconds must be an integer between 1 and 120"))
        })
        .transpose()?
        .unwrap_or(30);
    let path = executable()
        .ok_or_else(|| anyhow!("capa unavailable; install standalone capa or set KNIFE_CAPA"))?;
    let format = match session.bin.format {
        crate::model::Format::Pe => "pe",
        crate::model::Format::Elf => "elf",
        _ => return Err(anyhow!("capa provider currently accepts PE and ELF only")),
    };
    let workspace = crate::analysis::hashes::sha256_hex(&session.bytes);
    let key = format!("{workspace}:{}:{format}", executable_identity(&path));
    let cache = CACHE.get_or_init(|| Mutex::new(JsonCache::new(8, 32 * 1024 * 1024)));
    if let Some(raw) = cache
        .lock()
        .map_err(|_| anyhow!("capa cache poisoned"))?
        .get(&key)
    {
        let mut data = shape(&raw, args)?;
        data["diagnostics"] = raw["_knife_diagnostics"].clone();
        return Ok(data);
    }
    if args.get("cursor").is_some() {
        return Err(anyhow!(
            "capa continuation report expired; request the first page again"
        ));
    }
    let snapshot = TargetSnapshot::create("capa", &session.bytes)?;
    let output = run_process(
        &path,
        [
            OsString::from("-j"),
            OsString::from("-q"),
            OsString::from("-f"),
            OsString::from(format),
            snapshot.path().as_os_str().to_owned(),
        ],
        Duration::from_secs(timeout),
        8 * 1024 * 1024,
    )?;
    if !output.status.success() || output.truncated {
        return Err(anyhow!(
            "capa failed or exceeded output limit: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(2000)
                .collect::<String>()
        ));
    }
    let mut raw: Value = serde_json::from_slice(&output.stdout)?;
    if raw["meta"]["sample"]["sha256"].as_str() != Some(workspace.as_str()) {
        return Err(anyhow!(
            "capa report sample identity does not match workspace"
        ));
    }
    raw["_knife_diagnostics"] = json!(String::from_utf8_lossy(&output.stderr)
        .chars()
        .take(2000)
        .collect::<String>());
    let mut data = shape(&raw, args)?;
    data["diagnostics"] = raw["_knife_diagnostics"].clone();
    cache
        .lock()
        .map_err(|_| anyhow!("capa cache poisoned"))?
        .insert(key, raw);
    Ok(data)
}
fn shape(raw: &Value, args: &Value) -> Result<Value> {
    if raw["meta"]["flavor"].as_str() != Some("static") {
        return Err(anyhow!(
            "capa returned a non-static or unsupported result document"
        ));
    }
    let rules = raw["rules"]
        .as_object()
        .ok_or_else(|| anyhow!("capa result has no rule inventory"))?;
    let digest = crate::analysis::hashes::sha256_hex(&serde_json::to_vec(raw)?);
    if let Some(name) = args.get("rule").and_then(Value::as_str) {
        let rule = rules
            .get(name)
            .ok_or_else(|| anyhow!("no matched capa rule named '{name}'"))?;
        let matches = rule["matches"]
            .as_array()
            .ok_or_else(|| anyhow!("rule has no match array"))?;
        let page = PageWindow::from_args(
            args,
            matches.len(),
            5,
            20,
            &format!("capa_rule_matches:{digest}:{name}"),
        )?;
        let mut truncated = false;
        let rows: Vec<_> = matches
            .iter()
            .skip(page.offset)
            .take(page.limit)
            .map(|matched| {
                let mut budget = 512;
                bounded_tree(matched, 0, &mut budget, &mut truncated)
            })
            .collect();
        let source = rule["source"].as_str().unwrap_or("");
        let source_truncated = source.chars().count() > 4096;
        return Ok(
            json!({"provider":"capa","engine_version":raw["meta"]["version"],"result_sha256":digest,"matched":page.total,"returned":rows.len(),"next_cursor":page.next_cursor,"partial":page.next_cursor.is_some()||truncated||source_truncated,"rules":[{"name":name,"metadata":rule["meta"],"source":source.chars().take(4096).collect::<String>(),"source_truncated":source_truncated,"matches":rows,"tree_truncated":truncated,"locations":matches.iter().skip(page.offset).take(page.limit).filter_map(|pair|pair.as_array().and_then(|pair|pair.first())).collect::<Vec<_>>()}]}),
        );
    }
    let page = PageWindow::from_args(
        args,
        rules.len(),
        100,
        400,
        &format!("capa_capabilities:{digest}"),
    )?;
    let mut capped = false;
    let rows:Vec<_>=rules.iter().skip(page.offset).take(page.limit).map(|(name,rule)| {
        let matches=rule["matches"].as_array();
        capped |= matches.is_some_and(|values|values.len()>64);
        json!({"name":name,"metadata":rule["meta"],"match_count":matches.map_or(0,Vec::len),"locations":matches.into_iter().flatten().take(64).filter_map(|pair|pair.as_array().and_then(|pair|pair.first())).collect::<Vec<_>>()})
    }).collect();
    Ok(
        json!({"provider":"capa","engine_version":raw["meta"]["version"],"analysis":raw["meta"]["analysis"],"sample":raw["meta"]["sample"],"result_sha256":digest,"matched":page.total,"returned":rows.len(),"next_cursor":page.next_cursor,"partial":page.next_cursor.is_some()||capped,"rules":rows}),
    )
}

fn bounded_tree(value: &Value, depth: usize, budget: &mut usize, truncated: &mut bool) -> Value {
    if depth >= 16 || *budget == 0 {
        *truncated = true;
        return json!({"truncated":true});
    }
    *budget -= 1;
    match value {
        Value::Array(values) => {
            *truncated |= values.len() > 64;
            Value::Array(
                values
                    .iter()
                    .take(64)
                    .map(|value| bounded_tree(value, depth + 1, budget, truncated))
                    .collect(),
            )
        }
        Value::Object(values) => {
            *truncated |= values.len() > 64;
            Value::Object(
                values
                    .iter()
                    .take(64)
                    .map(|(key, value)| {
                        (
                            key.clone(),
                            bounded_tree(value, depth + 1, budget, truncated),
                        )
                    })
                    .collect(),
            )
        }
        Value::String(text) if text.chars().count() > 2048 => {
            *truncated = true;
            json!({"text_preview":text.chars().take(2048).collect::<String>(),"truncated":true})
        }
        _ => value.clone(),
    }
}

/// Correlate only known native address kinds. Managed tokens and unsupported
/// address kinds remain in provider JSON without fabricated native mappings.
pub fn evidence_locations(session: &Session, data: &Value) -> Vec<EvidenceLocation> {
    let mut locations = Vec::new();
    for rule in data["rules"].as_array().into_iter().flatten() {
        for location in rule["locations"].as_array().into_iter().flatten() {
            let Some(value) = location["value"].as_u64() else {
                continue;
            };
            let base = crate::analysis::engine::display_base(&session.bin);
            let (address, offset) = match location["type"].as_str() {
                Some("absolute") => (Some(value), None),
                Some("file") if value < session.bytes.len() as u64 => (None, Some(value)),
                _ => continue,
            };
            let offset = offset.or_else(|| {
                address
                    .and_then(|address| {
                        crate::analysis::engine::va_to_off(&session.bin, base, address)
                    })
                    .and_then(|offset| u64::try_from(offset).ok())
            });
            let address = address.or_else(|| {
                offset.and_then(|offset| {
                    crate::analysis::engine::off_to_va(&session.bin, base, offset)
                })
            });
            let record = EvidenceLocation {
                static_address: address.map(StaticVa),
                file_offset: offset.map(FileOffset),
                runtime_address: None,
                symbol: address.and_then(|address| {
                    session
                        .an
                        .function_at(address)
                        .map(|function| function.name.clone())
                }),
            };
            if !locations.contains(&record) {
                locations.push(record);
            }
            if locations.len() == 64 {
                return locations;
            }
        }
    }
    locations
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_locations_and_rule_metadata_survive_pagination() {
        let raw = json!({"meta":{"flavor":"static","version":"fixture"},"rules":{"rule-a":{"meta":{"namespace":"communication","att&ck":[{"id":"T1071"}]},"matches":[[{"type":"absolute","value":4096},{"success":true}]]},"rule-b":{"meta":{},"matches":[]}}});
        let result = shape(&raw, &json!({"limit":1})).unwrap();
        assert_eq!(result["matched"], 2);
        assert_eq!(result["partial"], true);
        let continued = shape(&raw, &json!({"limit":1,"cursor":result["next_cursor"]})).unwrap();
        assert_eq!(continued["rules"][0]["name"], "rule-b");
        assert!(continued["next_cursor"].is_null());
        assert_eq!(result["rules"][0]["locations"][0]["type"], "absolute");
        let details = shape(&raw, &json!({"rule":"rule-a","limit":1})).unwrap();
        assert_eq!(details["rules"][0]["matches"][0][1]["success"], true);
        assert!(shape(&raw, &json!({"rule":"missing"})).is_err());
        let mut budget = 3;
        let mut truncated = false;
        let bounded = bounded_tree(&json!([1, 2, 3, 4]), 0, &mut budget, &mut truncated);
        assert!(truncated);
        assert_eq!(bounded[2]["truncated"], true);
        assert!(shape(&json!({"meta":{"flavor":"dynamic"},"rules":{}}), &json!({})).is_err());
    }
}
