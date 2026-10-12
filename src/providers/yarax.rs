//! Native YARA-X rule compilation and bounded workspace scanning.

use crate::address::{FileOffset, StaticVa};
use crate::analysis::engine;
use crate::api::operations::{OperationDescriptor, ResultMode};
use crate::api::paging::PageWindow;
use crate::providers::ProviderStatus;
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::time::Duration;

const SOURCE_LIMIT: usize = 256 * 1024;
const RANGE_LIMIT: usize = 16 * 1024 * 1024;
const ROW_LIMIT: usize = 400;
const DEFAULT_TIMEOUT_MS: u64 = 2_000;
const MAX_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MATCHES_PER_PATTERN: usize = 100;
const MAX_MATCHES_PER_PATTERN: usize = 1_000;
const MATCH_PREVIEW_BYTES: usize = 64;

pub const OPERATION_NAMES: &[&str] = &["yarax_scan", "yarax_scan_range"];
pub const SYSTEM_OPERATION_NAMES: &[&str] = &["yarax_validate_rules"];

#[derive(Debug)]
pub struct ScanResult {
    pub data: Value,
    pub summary: String,
    pub locations: Vec<(Option<FileOffset>, Option<StaticVa>)>,
    pub partial: bool,
    pub continuation: Option<String>,
}

fn rules_props() -> Value {
    json!({
        "rules": {
            "type": "string",
            "maxLength": SOURCE_LIMIT,
            "description": "YARA rule source; rule files are not read implicitly"
        },
        "namespace": {"type": "string", "maxLength": 128},
        "include_private": {"type": "boolean"},
        "timeout_ms": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_MS},
        "max_matches_per_pattern": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_MATCHES_PER_PATTERN
        },
        "limit": {"type": "integer", "minimum": 1, "maximum": ROW_LIMIT},
        "cursor": {"type": "string"}
    })
}

pub fn catalog() -> Vec<OperationDescriptor> {
    let mut range_props = rules_props();
    if let Some(properties) = range_props.as_object_mut() {
        properties.insert(
            "address".into(),
            json!({"type": "string", "description": "static virtual address (0x...)"}),
        );
        properties.insert(
            "length".into(),
            json!({"type": "integer", "minimum": 1, "maximum": RANGE_LIMIT}),
        );
    }
    vec![
        OperationDescriptor::read(
            "yarax_scan",
            "Compile inline YARA rules and scan the exact Knife workspace with native YARA-X, returning rule metadata and bounded pattern matches.",
            rules_props(),
            &["rules"],
        )
        .with_result_mode(ResultMode::Paginated)
        .with_evidence(),
        OperationDescriptor::read(
            "yarax_scan_range",
            "Compile inline YARA rules and scan a bounded file-backed static-address range with native YARA-X.",
            range_props,
            &["rules", "address", "length"],
        )
        .with_result_mode(ResultMode::Paginated)
        .with_evidence(),
    ]
}

pub fn validation_descriptor() -> OperationDescriptor {
    let mut props = rules_props();
    if let Some(properties) = props.as_object_mut() {
        properties.remove("include_private");
        properties.remove("timeout_ms");
        properties.remove("max_matches_per_pattern");
    }
    OperationDescriptor::system_read(
        "yarax_validate_rules",
        "Compile inline YARA source without scanning a target; return warnings and a cursor-paginated rule inventory.",
        props,
        &["rules"],
    )
    .with_result_mode(ResultMode::Paginated)
}

pub fn is_operation(name: &str) -> bool {
    OPERATION_NAMES.contains(&name)
}

pub fn status() -> ProviderStatus {
    ProviderStatus {
        id: "yarax",
        name: "YARA-X",
        installed: true,
        executable: None,
        version: Some(yara_x::VERSION.to_string()),
        mode: "in_process_static",
        target_execution: false,
        license: "BSD-3-Clause; linked as a Rust library",
        operations: SYSTEM_OPERATION_NAMES
            .iter()
            .chain(OPERATION_NAMES.iter())
            .copied()
            .collect(),
        limitation: None,
    }
}

pub fn validate(args: &Value) -> Result<Value> {
    let compiled = compile(args)?;
    let scope = format!(
        "yarax_validate_rules:{}:{}",
        compiled.ruleset_sha256, compiled.namespace
    );
    let page = PageWindow::from_args(args, compiled.inventory.len(), 100, ROW_LIMIT, &scope)?;
    let rules: Vec<_> = compiled
        .inventory
        .into_iter()
        .skip(page.offset)
        .take(page.limit)
        .collect();
    Ok(json!({
        "provider": "yarax",
        "engine_version": yara_x::VERSION,
        "ruleset_sha256": compiled.ruleset_sha256,
        "namespace": compiled.namespace,
        "warnings": compiled.warnings,
        "matched": page.total,
        "returned": rules.len(),
        "next_cursor": page.next_cursor,
        "rules": rules,
    }))
}

pub fn scan(session: &Session, name: &str, args: &Value) -> Result<ScanResult> {
    let compiled = compile(args)?;
    let (data, base_file_offset, base_static_address, scope_suffix) = match name {
        "yarax_scan" => (&session.bytes[..], 0usize, None, "workspace".to_string()),
        "yarax_scan_range" => scan_range(session, args)?,
        other => return Err(anyhow!("unknown YARA-X operation '{other}'")),
    };
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(1, MAX_TIMEOUT_MS);
    let maximum_matches = args
        .get("max_matches_per_pattern")
        .and_then(Value::as_u64)
        .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
        .unwrap_or(DEFAULT_MATCHES_PER_PATTERN)
        .clamp(1, MAX_MATCHES_PER_PATTERN);
    let include_private = args
        .get("include_private")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut scanner = yara_x::Scanner::new(&compiled.rules);
    scanner
        .set_timeout(Duration::from_millis(timeout_ms))
        .max_matches_per_pattern(maximum_matches)
        .use_mmap(false);
    let results = scanner
        .scan(data)
        .map_err(|error| anyhow!("YARA-X scan failed: {error}"))?;
    let mut rows = Vec::new();
    let mut match_limit_may_have_truncated = false;
    for rule in results.matching_rules().include_private(include_private) {
        let mut patterns = Vec::new();
        for pattern in rule.patterns().include_private(include_private) {
            let matches: Vec<_> = pattern
                .matches()
                .map(|matched| {
                    let range = matched.range();
                    let absolute_offset = base_file_offset.saturating_add(range.start);
                    let file_offset = u64::try_from(absolute_offset).ok().map(FileOffset);
                    let static_address = base_static_address
                        .and_then(|base| base.get().checked_add(range.start as u64).map(StaticVa))
                        .or_else(|| {
                            file_offset.and_then(|offset| {
                                engine::off_to_va(
                                    &session.bin,
                                    engine::display_base(&session.bin),
                                    offset.get(),
                                )
                                .map(StaticVa)
                            })
                        });
                    let preview = &matched.data()[..matched.data().len().min(MATCH_PREVIEW_BYTES)];
                    json!({
                        "offset": file_offset.map(|offset| format!("0x{:x}", offset.get())),
                        "static_address": static_address.map(|address| format!("0x{:x}", address.get())),
                        "length": range.end.saturating_sub(range.start),
                        "xor_key": matched.xor_key(),
                        "preview_hex": hex(preview),
                        "preview_truncated": matched.data().len() > MATCH_PREVIEW_BYTES,
                    })
                })
                .collect();
            if matches.len() >= maximum_matches {
                // YARA-X returns at most this many matches. Equality cannot
                // distinguish an exact count from a capped one, so expose the
                // conservative interpretation to the agent.
                match_limit_may_have_truncated = true;
            }
            if !matches.is_empty() {
                patterns.push(json!({
                    "identifier": pattern.identifier(),
                    "kind": pattern_kind(pattern.kind()),
                    "private": pattern.is_private(),
                    "matches": matches,
                }));
            }
        }
        rows.push(json!({
            "identifier": rule.identifier(),
            "namespace": rule.namespace(),
            "private": rule.is_private(),
            "global": rule.is_global(),
            "tags": rule.tags().map(|tag| tag.identifier()).collect::<Vec<_>>(),
            "metadata": rule.metadata().into_json(),
            "patterns": patterns,
        }));
    }
    rows.sort_by(|left, right| {
        left["namespace"]
            .as_str()
            .cmp(&right["namespace"].as_str())
            .then(
                left["identifier"]
                    .as_str()
                    .cmp(&right["identifier"].as_str()),
            )
    });
    let scope = format!(
        "{name}:{}:{}:{scope_suffix}:{include_private}:{maximum_matches}",
        compiled.ruleset_sha256, timeout_ms
    );
    let raw_result = json!({
        "ruleset_sha256": &compiled.ruleset_sha256,
        "scope": &scope,
        "rules": &rows,
    });
    let result_digest =
        crate::analysis::hashes::sha256_hex(&serde_json::to_vec(&raw_result).unwrap_or_default());
    let page = PageWindow::from_args(args, rows.len(), 100, ROW_LIMIT, &scope)?;
    let selected: Vec<_> = rows
        .into_iter()
        .skip(page.offset)
        .take(page.limit)
        .collect();
    let evidence_locations = page_locations(&selected);
    let continuation = page.next_cursor.clone();
    Ok(ScanResult {
        data: json!({
            "provider": "yarax",
            "engine_version": yara_x::VERSION,
            "ruleset_sha256": compiled.ruleset_sha256,
            "result_sha256": result_digest,
            "namespace": compiled.namespace,
            "warnings": compiled.warnings,
            "timeout_ms": timeout_ms,
            "max_matches_per_pattern": maximum_matches,
            "match_limit_may_have_truncated": match_limit_may_have_truncated,
            "matched": page.total,
            "returned": selected.len(),
            "next_cursor": page.next_cursor,
            "rules": selected,
        }),
        summary: format!("YARA-X {name} result (result sha256 {result_digest})"),
        locations: evidence_locations,
        partial: continuation.is_some() || match_limit_may_have_truncated,
        continuation,
    })
}

fn page_locations(rows: &[Value]) -> Vec<(Option<FileOffset>, Option<StaticVa>)> {
    let mut locations = Vec::new();
    for row in rows {
        let Some(patterns) = row.get("patterns").and_then(Value::as_array) else {
            continue;
        };
        for pattern in patterns {
            let Some(matches) = pattern.get("matches").and_then(Value::as_array) else {
                continue;
            };
            for matched in matches {
                let file_offset = matched
                    .get("offset")
                    .and_then(Value::as_str)
                    .and_then(|value| parse_address(value).ok())
                    .map(FileOffset);
                let static_address = matched
                    .get("static_address")
                    .and_then(Value::as_str)
                    .and_then(|value| parse_address(value).ok())
                    .map(StaticVa);
                let location = (file_offset, static_address);
                if !locations.contains(&location) {
                    locations.push(location);
                }
                if locations.len() == 64 {
                    return locations;
                }
            }
        }
    }
    locations
}

struct CompiledRules {
    rules: yara_x::Rules,
    ruleset_sha256: String,
    namespace: String,
    warnings: Vec<String>,
    inventory: Vec<Value>,
}

fn compile(args: &Value) -> Result<CompiledRules> {
    let source = args
        .get("rules")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing `rules`"))?;
    if source.len() > SOURCE_LIMIT {
        return Err(anyhow!("YARA source exceeds the {SOURCE_LIMIT}-byte limit"));
    }
    let namespace = args
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    if namespace.len() > 128 {
        return Err(anyhow!("YARA namespace exceeds 128 bytes"));
    }
    let mut compiler = yara_x::Compiler::new();
    compiler.new_namespace(namespace);
    compiler
        .add_source(source)
        .map_err(|error| anyhow!("YARA-X compilation failed: {error}"))?;
    let warnings = compiler
        .warnings()
        .iter()
        .map(ToString::to_string)
        .collect();
    let rules = compiler.build();
    let inventory = rules
        .iter()
        .map(|rule| {
            json!({
                "identifier": rule.identifier(),
                "namespace": rule.namespace(),
                "private": rule.is_private(),
                "global": rule.is_global(),
                "tags": rule.tags().map(|tag| tag.identifier()).collect::<Vec<_>>(),
                "metadata": rule.metadata().into_json(),
                "patterns": rule.patterns().include_private(true).map(|pattern| json!({
                    "identifier": pattern.identifier(),
                    "kind": pattern_kind(pattern.kind()),
                    "private": pattern.is_private(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(CompiledRules {
        rules,
        ruleset_sha256: crate::analysis::hashes::sha256_hex(source.as_bytes()),
        namespace: namespace.to_string(),
        warnings,
        inventory,
    })
}

fn scan_range<'a>(
    session: &'a Session,
    args: &Value,
) -> Result<(&'a [u8], usize, Option<StaticVa>, String)> {
    let encoded = args
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing `address`"))?;
    let address = parse_address(encoded)?;
    let length = args
        .get("length")
        .and_then(Value::as_u64)
        .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
        .ok_or_else(|| anyhow!("missing `length`"))?;
    if !(1..=RANGE_LIMIT).contains(&length) {
        return Err(anyhow!(
            "range length must be between 1 and {RANGE_LIMIT} bytes"
        ));
    }
    let offset = engine::va_to_off(&session.bin, engine::display_base(&session.bin), address)
        .ok_or_else(|| anyhow!("static address {encoded} is not file-backed"))?;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= session.bytes.len())
        .ok_or_else(|| anyhow!("requested range exceeds the workspace bytes"))?;
    for relative in [0usize, length.saturating_sub(1)] {
        let file_offset = u64::try_from(offset.saturating_add(relative))
            .map_err(|_| anyhow!("file offset overflow"))?;
        let expected = address
            .checked_add(relative as u64)
            .ok_or_else(|| anyhow!("static address overflow"))?;
        if engine::off_to_va(
            &session.bin,
            engine::display_base(&session.bin),
            file_offset,
        ) != Some(expected)
        {
            return Err(anyhow!(
                "requested range crosses a non-contiguous image mapping"
            ));
        }
    }
    Ok((
        &session.bytes[offset..end],
        offset,
        Some(StaticVa(address)),
        format!("0x{address:x}+0x{length:x}"),
    ))
}

fn parse_address(value: &str) -> Result<u64> {
    let value = value.trim();
    let raw = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(raw, 16).map_err(|_| anyhow!("bad static address '{value}'"))
}

fn pattern_kind(kind: yara_x::PatternKind) -> &'static str {
    match kind {
        yara_x::PatternKind::Text => "text",
        yara_x::PatternKind::Hex => "hex",
        yara_x::PatternKind::Regexp => "regexp",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
        rule marker : test {
            meta:
                purpose = "fixture"
            strings:
                $mz = { 4d 5a }
            condition:
                $mz at 0
        }
    "#;

    #[test]
    fn validation_returns_rule_inventory_without_a_target() {
        let value = validate(&json!({"rules": RULES})).unwrap();
        assert_eq!(value["provider"], "yarax");
        assert_eq!(value["matched"], 1);
        assert_eq!(value["rules"][0]["identifier"], "marker");
        assert_eq!(value["rules"][0]["patterns"][0]["kind"], "hex");
    }

    #[test]
    fn malformed_and_oversized_rules_fail_closed() {
        assert!(validate(&json!({"rules": "rule broken {"})).is_err());
        assert!(validate(&json!({"rules": "x".repeat(SOURCE_LIMIT + 1)})).is_err());
    }

    #[test]
    fn catalog_is_typed_bounded_and_evidence_aware() {
        assert_eq!(catalog().len(), OPERATION_NAMES.len());
        for operation in catalog() {
            assert!(operation.emits_evidence);
            assert_eq!(operation.result_mode, ResultMode::Paginated);
            assert_eq!(
                operation.params["properties"]["rules"]["maxLength"],
                SOURCE_LIMIT
            );
        }
        assert_eq!(
            validation_descriptor().target,
            crate::api::operations::TargetRequirement::None
        );
    }
}
