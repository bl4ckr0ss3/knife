use reknife::api::evidence::{StatementKind, EVIDENCE_CONTRACT_VERSION};
use reknife::api::operations::{OperationAccess, ResultMode, TargetRequirement};
use reknife::api::results::ResultStore;
use reknife::tools;
use reknife::workspace::Session;
use serde_json::json;

fn fixture_session() -> (std::path::PathBuf, Session) {
    let root = std::env::temp_dir().join(format!(
        "knife-agent-baseline-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.exe");
    let database = root.join("fixture.json");
    std::fs::write(&target, reknife::formats::fixture::pe_with_driver()).unwrap();
    let session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "agent baseline test",
    )
    .unwrap();
    (root, session)
}

#[test]
fn wasm_container_functions_remain_paginated_without_native_analysis() {
    let (root, _) = fixture_session();
    let target = root.join("fixture.wasm");
    let bytes = [
        0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 7, 7, 1, 3, 114, 117, 110, 0,
        0, 10, 4, 1, 2, 0, 11,
    ];
    std::fs::write(&target, bytes).unwrap();
    let session = Session::open_data(target.to_str().unwrap(), None).unwrap();
    let functions = tools::dispatch(&session, "list_functions", &json!({"limit": 1})).unwrap();
    assert_eq!(functions["returned"], 1);
    assert!(functions["functions"][0]["blocks"].is_null());
    assert!(tools::dispatch(&session, "wat", &json!({})).is_ok());
    assert!(tools::dispatch(&session, "disassemble", &json!({"selector": "run"})).is_err());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn function_explanation_links_its_inputs_to_evidence() {
    let (root, session) = fixture_session();
    let address = session.an.functions[0].addr;
    let result = tools::dispatch(
        &session,
        "explain_function",
        &json!({"selector":format!("0x{address:x}")}),
    )
    .unwrap();
    assert_eq!(result["evidence"][0]["producer"], "explain_function");
    assert_eq!(
        result["evidence"][0]["locations"][0]["static_address"],
        address
    );
    assert!(result["data"]["instructions"]["data"].is_object());
    assert!(result["data"]["pseudocode"].is_object());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn agent_ledger_persists_questions_and_validates_evidence_links() {
    let (root, mut session) = fixture_session();
    let asked = tools::dispatch_mut(
        &mut session,
        "investigation_ask",
        &json!({"question":"Is this an input validator?"}),
    )
    .unwrap();
    let id = asked["result"]["hypothesis_id"].as_u64().unwrap();
    let status = tools::dispatch(&session, "session_status", &json!({})).unwrap();
    let evidence = status["evidence"][0].clone();
    tools::dispatch_mut(
        &mut session,
        "investigation_record_evidence",
        &json!({"evidence":evidence}),
    )
    .unwrap();
    let linked = tools::dispatch_mut(
        &mut session,
        "investigation_link_evidence",
        &json!({"hypothesis_id":id,"evidence_id":evidence["id"],"contradicts":false}),
    )
    .unwrap();
    assert_eq!(linked["result"]["status"], "supported");
    let step = tools::dispatch_mut(
        &mut session,
        "investigation_add_plan_step",
        &json!({"text":"Establish target identity"}),
    )
    .unwrap()["result"]["step_id"]
        .clone();
    assert!(tools::dispatch_mut(
        &mut session,
        "investigation_update_plan_step",
        &json!({"step_id":step,"status":"completed"})
    )
    .is_err());
    tools::dispatch_mut(
        &mut session,
        "investigation_update_plan_step",
        &json!({"step_id":step,"status":"completed","evidence_ids":[evidence["id"]]}),
    )
    .unwrap();
    tools::dispatch_mut(&mut session,"investigation_append_message",&json!({"role":"assistant","text":"Observed target identity; behavior remains unresolved.","evidence_ids":[evidence["id"]]})).unwrap();
    assert!(tools::dispatch_mut(
        &mut session,
        "investigation_append_message",
        &json!({"role":"assistant","text":"Unsupported claim","evidence_ids":["missing"]})
    )
    .is_err());
    let saved = tools::dispatch(&session, "investigation_status", &json!({})).unwrap();
    assert_eq!(saved["message_count"], 2);
    assert_eq!(saved["messages"][0]["role"], "assistant");
    assert_eq!(saved["hypothesis_count"], 1);
    assert_eq!(saved["plan_count"], 1);
    assert_eq!(saved["plan"][0]["status"], "completed");
    assert_eq!(saved["evidence_count"], 1);
    assert_eq!(
        tools::dispatch(&session, "investigation_conflicts", &json!({})).unwrap()["matched"],
        0
    );
    tools::dispatch_mut(
        &mut session,
        "investigation_link_evidence",
        &json!({"hypothesis_id":id,"evidence_id":evidence["id"],"contradicts":true}),
    )
    .unwrap();
    let conflicts = tools::dispatch(&session, "investigation_conflicts", &json!({})).unwrap();
    assert_eq!(conflicts["matched"], 1);
    assert_eq!(
        conflicts["conflicts"][0]["hypothesis"]["status"],
        "unresolved"
    );
    assert_eq!(
        conflicts["conflicts"][0]["supporting_evidence"][0]["id"],
        evidence["id"]
    );
    assert_eq!(
        tools::dispatch(
            &session,
            "investigation_get_evidence",
            &json!({"evidence_id":evidence["id"]})
        )
        .unwrap(),
        evidence
    );
    let mut tampered = evidence.clone();
    tampered["summary"] = json!("Changed claim");
    assert!(tools::dispatch_mut(
        &mut session,
        "investigation_record_evidence",
        &json!({"evidence":tampered})
    )
    .is_err());
    assert!(tools::dispatch_mut(
        &mut session,
        "investigation_link_evidence",
        &json!({"hypothesis_id":id,"evidence_id":"unknown","contradicts":true})
    )
    .is_err());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn string_usage_returns_bounded_references_and_no_absence_claim() {
    let (root, session) = fixture_session();
    let result = tools::dispatch(
        &session,
        "trace_string_usage",
        &json!({"query":"","limit":1}),
    )
    .unwrap();
    assert!(result["data"]["returned"].as_u64().unwrap() <= 1);
    assert_eq!(result["evidence"][0]["producer"], "trace_string_usage");
    let empty = tools::dispatch(
        &session,
        "trace_string_usage",
        &json!({"query":"impossible_fixture_string_123456"}),
    )
    .unwrap();
    assert_eq!(empty["data"]["matched"], 0);
    assert!(empty["evidence"][0]["limitations"][0]
        .as_str()
        .unwrap()
        .contains("not proof"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn input_validation_workflow_preserves_candidate_status_and_bounds() {
    let (root, session) = fixture_session();
    let address = session.an.functions[0].addr;
    let result = tools::dispatch(
        &session,
        "inspect_input_validation",
        &json!({"address":format!("0x{address:x}")}),
    )
    .unwrap();
    assert_eq!(
        result["evidence"][0]["producer"],
        "inspect_input_validation"
    );
    assert_eq!(result["evidence"][0]["statements"][0]["kind"], "inference");
    assert!(result["data"]["instructions_inspected"].as_u64().unwrap() > 0);
    assert!(result["data"]["candidate_sites"].as_array().unwrap().len() <= 64);
    assert!(result["data"]["argument_provenance"].is_object());
    assert!(result["evidence"][0]["limitations"][0]
        .as_str()
        .unwrap()
        .contains("does not prove"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn engine_comparison_preserves_disagreement_and_unknown_states() {
    let (root, session) = fixture_session();
    let address = session.an.functions[0].addr;
    let result = tools::dispatch(
        &session,
        "compare_engine_findings",
        &json!({"address":format!("0x{address:x}")}),
    )
    .unwrap();
    assert_eq!(result["evidence"][0]["producer"], "compare_engine_findings");
    assert_eq!(result["data"]["comparisons"].as_array().unwrap().len(), 2);
    assert!(result["data"]["ghidra"].is_null());
    assert!(tools::dispatch(
        &session,
        "compare_engine_findings",
        &json!({"address":format!("0x{address:x}"),"include_ghidra":"yes"})
    )
    .is_err());
    if reknife::providers::ghidra::executable().is_none() {
        let extended = tools::dispatch(
            &session,
            "compare_engine_findings",
            &json!({"address":format!("0x{address:x}"),"include_ghidra":true}),
        )
        .unwrap();
        assert_eq!(extended["data"]["comparisons"].as_array().unwrap().len(), 4);
        assert_eq!(extended["data"]["comparisons"][2]["status"], "unknown");
        assert_eq!(extended["data"]["comparisons"][3]["status"], "unknown");
        assert_eq!(extended["partial"], true);
    }
    for field in result["data"]["comparisons"].as_array().unwrap() {
        assert!(
            ["agreement", "disagreement", "unknown"].contains(&field["status"].as_str().unwrap())
        );
    }
    if result["data"]["rizin"]["unavailable"].is_string() {
        assert_eq!(result["data"]["unknown_fields"], 2);
    } else {
        assert!(result["evidence"].as_array().unwrap().len() >= 2);
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn parsed_target_does_not_claim_zero_recovered_functions() {
    let (root, session) = fixture_session();
    let data = Session::open_data(
        &session.bin.path,
        session.db.path().and_then(|path| path.to_str()),
    )
    .unwrap();
    let info = tools::dispatch(&data, "info", &json!({})).unwrap();
    assert_eq!(info["code_analyzed"], false);
    assert!(info["functions"].is_null());
    assert!(info["imports"].as_u64().unwrap() > 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn capa_locations_preserve_native_file_and_managed_address_distinctions() {
    let (root, session) = fixture_session();
    let address = session.an.functions[0].addr;
    let data = json!({"rules":[{"locations":[{"type":"absolute","value":address},{"type":"absolute","value":address},{"type":"file","value":0},{"type":"dn token","value":address},{"type":"file","value":u64::MAX}]}]});
    let locations = reknife::providers::capa::evidence_locations(&session, &data);
    assert_eq!(locations.len(), 2);
    assert_eq!(locations[0].static_address.unwrap().get(), address);
    assert!(locations[0].file_offset.is_some());
    assert_eq!(locations[1].file_offset.unwrap().get(), 0);
    assert!(locations
        .iter()
        .all(|location| location.runtime_address.is_none()));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn session_status_establishes_identity_coverage_and_limitations() {
    let (root, session) = fixture_session();
    let first = tools::dispatch(&session, "session_status", &json!({})).unwrap();
    let second = tools::dispatch(&session, "session_status", &json!({})).unwrap();

    assert_eq!(first["contract_version"], EVIDENCE_CONTRACT_VERSION);
    assert_eq!(first["data"]["target"]["sha256"], session.db.sha256);
    assert_eq!(
        first["data"]["target"]["workspace_sha256"],
        session.db.sha256
    );
    assert_eq!(first["data"]["target"]["staged_patch_bytes"], 0);
    assert_eq!(first["data"]["target"]["format"], "PE");
    assert_eq!(first["data"]["analysis_truncated"], false);
    let operations = first["data"]["operations"].as_array().unwrap();
    assert_eq!(operations.len(), tools::catalog().len());
    assert!(operations.iter().any(|operation| {
        operation["name"] == "session_status"
            && operation["available"] == true
            && operation["emits_evidence"] == true
    }));
    assert!(operations.iter().any(|operation| {
        operation["name"] == "elf_structure"
            && operation["available"] == false
            && operation["unavailable_reason"] == "the active target is not ELF"
    }));
    assert_eq!(first["partial"], false);
    assert_eq!(first["evidence"][0]["id"], second["evidence"][0]["id"]);
    assert_eq!(first["evidence"][0]["kind"], "target_identity");
    assert_eq!(
        first["evidence"][0]["statements"][0]["kind"],
        serde_json::to_value(StatementKind::Observation).unwrap()
    );
    assert!(first["evidence"][0]["limitations"]
        .as_array()
        .is_some_and(|limits| !limits.is_empty()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn read_catalog_exposes_machine_readable_operation_policy() {
    let catalog = tools::read_catalog();
    let status = catalog
        .iter()
        .find(|operation| operation.name == "session_status")
        .expect("session_status is discoverable");
    assert_eq!(status.access, OperationAccess::ReadOnly);
    assert_eq!(status.target, TargetRequirement::Active);
    assert!(catalog
        .iter()
        .all(|operation| operation.access == OperationAccess::ReadOnly));
    assert_eq!(
        catalog
            .iter()
            .find(|operation| operation.name == "list_functions")
            .unwrap()
            .result_mode,
        ResultMode::Paginated
    );

    let mutations = tools::mutation_catalog();
    assert_eq!(mutations.len(), 10);
    assert!(mutations
        .iter()
        .all(|operation| operation.access == OperationAccess::ProjectWrite));
    assert_eq!(
        tools::catalog().len(),
        tools::system_catalog().len() + catalog.len() + mutations.len()
    );
}

#[test]
fn shared_mutation_dispatch_updates_the_project_without_touching_the_input() {
    let (root, mut session) = fixture_session();
    let original = std::fs::read(&session.bin.path).unwrap();
    let function = session
        .an
        .functions
        .first()
        .expect("fixture has a function");
    let address = function.addr;
    let selector = function.name.clone();

    let named = tools::dispatch_mut(
        &mut session,
        "set_name",
        &json!({"address": format!("0x{address:x}"), "name": "agent_entry"}),
    )
    .unwrap();
    assert_eq!(named["ok"], true);
    assert!(session.db.names.values().any(|name| name == "agent_entry"));

    let prototype = tools::dispatch_mut(
        &mut session,
        "set_prototype",
        &json!({"function": selector, "returns": "int", "params": ["void *"]}),
    )
    .unwrap();
    assert_eq!(prototype["ok"], true);

    let patch = tools::dispatch_mut(
        &mut session,
        "stage_patch",
        &json!({"offset": "0x0", "bytes": "7f"}),
    )
    .unwrap();
    assert_eq!(patch["staged"], 1);
    assert_eq!(std::fs::read(&session.bin.path).unwrap(), original);
    assert_eq!(session.db.patches.len(), 1);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn function_pages_continue_without_repeating_rows() {
    let (root, session) = fixture_session();
    let first = tools::dispatch(&session, "list_functions", &json!({"limit": 1})).unwrap();
    let cursor = first["next_cursor"]
        .as_str()
        .expect("fixture produces another page");
    let second = tools::dispatch(
        &session,
        "list_functions",
        &json!({"limit": 1, "cursor": cursor}),
    )
    .unwrap();
    assert_eq!(first["returned"], 1);
    assert_eq!(second["returned"], 1);
    assert_ne!(
        first["functions"][0]["addr"],
        second["functions"][0]["addr"]
    );
    assert!(tools::dispatch(
        &session,
        "list_functions",
        &json!({"filter": "different-query", "cursor": cursor}),
    )
    .is_err());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn address_context_preserves_static_and_file_locations_as_evidence() {
    let (root, session) = fixture_session();
    let function = session
        .an
        .functions
        .first()
        .expect("fixture has a function");
    let address = function.addr;
    let expected_offset = reknife::analysis::engine::va_to_off(
        &session.bin,
        reknife::analysis::engine::display_base(&session.bin),
        address,
    )
    .expect("fixture function is file-backed");

    let context = tools::dispatch(
        &session,
        "inspect_address_context",
        &json!({"address": format!("0x{address:x}")}),
    )
    .unwrap();
    assert_eq!(context["contract_version"], EVIDENCE_CONTRACT_VERSION);
    assert_eq!(context["data"]["static_address"], format!("0x{address:x}"));
    assert_eq!(
        context["data"]["file_offset"],
        format!("0x{expected_offset:x}")
    );
    assert_eq!(
        context["data"]["containing_function"]["name"],
        function.name
    );
    assert_eq!(
        context["evidence"][0]["locations"][0]["static_address"],
        address
    );
    assert_eq!(
        context["evidence"][0]["locations"][0]["file_offset"],
        expected_offset
    );
    assert!(context["evidence"][0]["statements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|statement| statement["kind"] == "observation"));
    assert!(context["evidence"][0]["statements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|statement| statement["kind"] == "inference"));

    let mapped = tools::dispatch(
        &session,
        "address_to_file_offset",
        &json!({"address": format!("0x{address:x}")}),
    )
    .unwrap();
    assert_eq!(
        mapped["data"]["file_offset"],
        format!("0x{expected_offset:x}")
    );
    let containing = tools::dispatch(
        &session,
        "resolve_containing_function",
        &json!({"address": format!("0x{address:x}")}),
    )
    .unwrap();
    assert_eq!(containing["data"]["name"], function.name);

    let bytes = tools::dispatch(
        &session,
        "read_bytes",
        &json!({"address": format!("0x{address:x}"), "length": 17}),
    )
    .unwrap();
    assert_eq!(bytes.as_str().unwrap().lines().count(), 2);
    assert!(tools::dispatch(
        &session,
        "read_bytes",
        &json!({"address": format!("0x{address:x}"), "length": 4097}),
    )
    .is_err());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn instruction_pages_are_structured_scoped_and_continuable() {
    let (root, session) = fixture_session();
    let function = session
        .an
        .functions
        .first()
        .expect("fixture has a function");
    let address = function.addr;
    let first = tools::dispatch(
        &session,
        "read_function_instructions",
        &json!({"address": format!("0x{address:x}"), "limit": 1}),
    )
    .unwrap();
    assert_eq!(first["contract_version"], EVIDENCE_CONTRACT_VERSION);
    assert_eq!(first["data"]["returned"], 1);
    assert!(first["data"]["instructions"][0]["bytes"].is_string());
    assert!(first["data"]["instructions"][0]["mnemonic"].is_string());

    if let Some(cursor) = first["continuation"].as_str() {
        assert_eq!(first["partial"], true);
        assert_eq!(first["data"]["next_cursor"], cursor);
        let second = tools::dispatch(
            &session,
            "read_function_instructions",
            &json!({
                "selector": format!("0x{address:x}"),
                "limit": 1,
                "cursor": cursor,
            }),
        )
        .unwrap();
        assert_ne!(
            first["data"]["instructions"][0]["address"],
            second["data"]["instructions"][0]["address"]
        );
        assert!(tools::dispatch(
            &session,
            "read_function_instructions",
            &json!({
                "selector": format!("0x{address:x}"),
                "start_address": format!("0x{:x}", address + 1),
                "cursor": cursor,
            }),
        )
        .is_err());
    } else {
        assert_eq!(first["partial"], false);
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn external_provider_catalog_is_discoverable_and_bounded() {
    let store = ResultStore::default();
    let status = tools::dispatch_system(&store, "provider_status", &json!({})).unwrap();
    let rizin = status["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|provider| provider["id"] == "rizin")
        .expect("Rizin provider is registered even when not installed");
    assert_eq!(rizin["target_execution"], false);
    assert!(rizin["operations"].as_array().unwrap().len() >= 15);
    let yarax = status["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|provider| provider["id"] == "yarax")
        .expect("native YARA-X provider is registered");
    assert_eq!(yarax["installed"], true);
    assert_eq!(yarax["target_execution"], false);
    assert_eq!(yarax["license"], "BSD-3-Clause; linked as a Rust library");

    let catalog = tools::read_catalog();
    let functions = catalog
        .iter()
        .find(|operation| operation.name == "rizin_functions")
        .expect("Rizin functions are discoverable");
    assert_eq!(functions.access, OperationAccess::ReadOnly);
    assert_eq!(functions.result_mode, ResultMode::Paginated);
    assert!(functions.emits_evidence);

    if !rizin["installed"].as_bool().unwrap_or(false) {
        return;
    }
    let (root, session) = fixture_session();
    let info = tools::dispatch(&session, "rizin_info", &json!({})).unwrap();
    assert_eq!(info["contract_version"], EVIDENCE_CONTRACT_VERSION);
    assert_eq!(info["data"]["provider"], "rizin");
    assert_eq!(info["partial"], false);
    assert_eq!(info["evidence"][0]["producer"], "rizin_info");

    let page = tools::dispatch(&session, "rizin_functions", &json!({"limit": 1})).unwrap();
    assert_eq!(page["data"]["provider"], "rizin");
    assert!(page["data"]["returned"].as_u64().unwrap() <= 1);
    assert_eq!(page["evidence"][0]["statements"][0]["kind"], "inference");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn yarax_validates_and_scans_exact_workspace_locations() {
    let store = ResultStore::default();
    let rules = r#"
        rule pe_header : fixture {
            meta:
                purpose = "agent provider test"
            strings:
                $mz = { 4d 5a }
            condition:
                $mz at 0
        }
    "#;
    let validated = tools::dispatch_system(
        &store,
        "yarax_validate_rules",
        &json!({"rules": rules, "limit": 1}),
    )
    .unwrap();
    assert_eq!(validated["provider"], "yarax");
    assert_eq!(validated["returned"], 1);
    assert_eq!(validated["rules"][0]["identifier"], "pe_header");

    let (root, session) = fixture_session();
    let scanned = tools::dispatch(
        &session,
        "yarax_scan",
        &json!({
            "rules": rules,
            "timeout_ms": 1_000,
            "max_matches_per_pattern": 4,
        }),
    )
    .unwrap();
    assert_eq!(scanned["contract_version"], EVIDENCE_CONTRACT_VERSION);
    assert_eq!(scanned["data"]["provider"], "yarax");
    assert_eq!(scanned["data"]["matched"], 1);
    assert_eq!(scanned["data"]["result_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(scanned["data"]["match_limit_may_have_truncated"], false);
    assert_eq!(
        scanned["data"]["rules"][0]["patterns"][0]["matches"][0]["offset"],
        "0x0"
    );
    assert_eq!(scanned["evidence"][0]["statements"][0]["kind"], "inference");
    assert_eq!(scanned["evidence"][0]["locations"][0]["file_offset"], 0);

    let function = session.an.functions.first().expect("fixture has code");
    let offset = reknife::analysis::engine::va_to_off(
        &session.bin,
        reknife::analysis::engine::display_base(&session.bin),
        function.addr,
    )
    .unwrap();
    let signature = format!(
        "{:02x} {:02x}",
        session.bytes[offset],
        session.bytes[offset + 1]
    );
    let range_rules =
        format!("rule function_prefix {{ strings: $a = {{ {signature} }} condition: $a at 0 }}");
    let ranged = tools::dispatch(
        &session,
        "yarax_scan_range",
        &json!({
            "rules": range_rules,
            "address": format!("0x{:x}", function.addr),
            "length": 16,
        }),
    )
    .unwrap();
    assert_eq!(ranged["data"]["matched"], 1);
    assert_eq!(
        ranged["data"]["rules"][0]["patterns"][0]["matches"][0]["static_address"],
        format!("0x{:x}", function.addr)
    );
    assert_eq!(
        ranged["evidence"][0]["locations"][0]["static_address"],
        function.addr
    );
    let _ = std::fs::remove_dir_all(root);
}
