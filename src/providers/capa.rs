//! Fixed-command adapter for standalone capa capability analysis.
use super::process::{executable_identity, find_on_path, run_process, JsonCache, TargetSnapshot};
use super::ProviderStatus;
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
        operations: vec!["capa_capabilities"],
        limitation: executable
            .is_none()
            .then(|| "Install standalone capa or set KNIFE_CAPA to its executable".into()),
    }
}
pub fn descriptor() -> OperationDescriptor {
    OperationDescriptor::read("capa_capabilities","Independent capa capability rules, ATT&CK/MBC metadata and typed match locations from static workspace bytes.",json!({"limit":{"type":"integer","minimum":1,"maximum":400},"cursor":{"type":"string"}}),&[]).with_result_mode(ResultMode::Paginated).with_evidence()
}
pub fn dispatch(session: &Session, args: &Value) -> Result<Value> {
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
        Duration::from_secs(30),
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
        assert!(shape(&json!({"meta":{"flavor":"dynamic"},"rules":{}}), &json!({})).is_err());
    }
}
