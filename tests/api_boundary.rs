use reknife::address::{PointerValue, StaticVa};
use reknife::api::binary_summary::{BinarySummary, ImageAddress};
use reknife::api::driver_surface::DriverSurfaceQuery;
use reknife::api::edits::{apply_analyst_edit, AnalystEdit, AnalystEditKind};
use reknife::api::facts::{self, FactKind, FactQuery, TypeLibraryOperation};
use reknife::api::graphs::{self as graph_api, GraphKind, GraphQuery};
use reknife::api::listing::{
    file_hex_window, FileHexQuery, HexQuery, LinearLocation, LinearQuery, LinearRow, ListingIndex,
    StringQuery,
};
use reknife::api::navigation::{self, DirectPathQuery, FunctionQuery, XrefDirection};
use reknife::api::patches;
use reknife::api::risk_signals;
use reknife::api::symbols::{self as symbol_api, SymbolQuery};
use reknife::api::TargetIdentity;
use reknife::workspace::Session;

#[test]
fn raw_file_windows_preserve_overlapping_image_mappings() {
    let mut binary =
        reknife::model::Binary::stub(reknife::model::Format::Elf, reknife::model::Arch::X86_64);
    binary.sections = vec![
        reknife::model::Section {
            name: "first".into(),
            vaddr: 0x1000,
            vsize: 0x20,
            file_off: 0,
            file_size: 0x20,
            entropy: 0.0,
            read: true,
            write: false,
            exec: false,
        },
        reknife::model::Section {
            name: "alias".into(),
            vaddr: 0x2000,
            vsize: 0x20,
            file_off: 0,
            file_size: 0x20,
            entropy: 0.0,
            read: true,
            write: false,
            exec: false,
        },
    ];
    let window = file_hex_window(
        &binary,
        &[0u8; 32],
        0,
        FileHexQuery {
            file_offset: reknife::address::FileOffset(0),
            length: 16,
        },
    )
    .unwrap();
    assert_eq!(window.rows[0].mappings.len(), 2);
    assert_eq!(window.rows[0].mappings[0].address, StaticVa(0x1000));
    assert_eq!(window.rows[0].mappings[1].address, StaticVa(0x2000));
}

#[test]
fn target_identity_matches_the_existing_session_contract() {
    let root = std::env::temp_dir().join(format!(
        "knife-api-boundary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.exe");
    let database = root.join("fixture.json");
    let mut fixture = reknife::formats::fixture::pe_with_iat_call();
    fixture[reknife::formats::fixture::OPT + 0x18..reknife::formats::fixture::OPT + 0x20]
        .copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    std::fs::write(&target, fixture).unwrap();

    let mut session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "typed API boundary test",
    )
    .unwrap();
    let identity = TargetIdentity::from_session(&session);

    assert_eq!(identity.path, session.bin.path);
    assert_eq!(identity.sha256, session.db.sha256);
    assert_eq!(
        identity.workspace_sha256,
        reknife::analysis::hashes::sha256_hex(&session.bytes)
    );
    assert_eq!(identity.staged_patch_bytes, session.db.patches.len());
    assert_eq!(identity.format, session.bin.format.label());
    assert_eq!(identity.architecture, session.bin.arch.label());
    assert_eq!(identity.image_base, session.bin.image_base);
    assert_eq!(identity.entry, session.bin.entry);
    assert_eq!(identity.functions_recovered, session.an.functions.len());
    assert_eq!(
        identity.functions_named,
        session.an.functions.iter().filter(|f| f.named).count()
    );

    let functions = navigation::functions(&session, &FunctionQuery::default());
    assert_eq!(functions.len(), session.an.functions.len());
    let named = navigation::functions(
        &session,
        &FunctionQuery {
            name_contains: None,
            named_only: true,
            limit: Some(1),
        },
    );
    assert!(named.len() <= 1);
    assert!(named.iter().all(|function| function.named));

    let caller = session
        .an
        .functions
        .iter()
        .find(|function| !function.calls.is_empty())
        .expect("fixture has a recovered caller");
    let outgoing = navigation::xrefs(&session, StaticVa(caller.addr), XrefDirection::From);
    assert_eq!(outgoing.len(), caller.calls.len());
    assert_eq!(outgoing[0].address.get(), caller.calls[0]);

    let incoming = navigation::xrefs(&session, StaticVa(caller.calls[0]), XrefDirection::To);
    assert!(incoming.iter().any(|reference| {
        session
            .an
            .function_at(reference.address.get())
            .is_some_and(|function| function.addr == caller.addr)
    }));
    let paths = navigation::direct_paths(
        &session,
        &DirectPathQuery {
            selector: format!("0x{:x}", caller.calls[0]),
            maximum_paths: 12,
        },
    )
    .unwrap();
    assert!(!paths.is_empty());
    assert!(paths.iter().all(|path| !path.hops.is_empty()));
    assert!(navigation::direct_paths(
        &session,
        &DirectPathQuery {
            selector: "ffffffffffffffff".into(),
            maximum_paths: 12,
        },
    )
    .unwrap()
    .is_empty());

    let listing = ListingIndex::from_session(&session);
    let function = session
        .an
        .functions
        .first()
        .expect("fixture has a recovered function");
    let by_name = listing.disassemble(&session, &function.name).unwrap();
    let by_address = listing
        .disassemble(&session, &format!("0x{:x}", function.addr))
        .unwrap();
    assert!(!by_name.is_empty());
    assert_eq!(
        by_name
            .iter()
            .map(|line| line.address())
            .collect::<Vec<_>>(),
        by_address
            .iter()
            .map(|line| line.address())
            .collect::<Vec<_>>()
    );
    assert!(listing.disassemble(&session, "ffffffffffffffff").is_err());
    let strings = listing.strings(&session, &StringQuery::default());
    assert_eq!(
        strings.len(),
        reknife::listing::string_map(
            &session.bin,
            &session.bytes,
            reknife::analysis::engine::display_base(&session.bin)
        )
        .len()
    );
    assert!(strings.iter().all(|string| {
        string.file_offset.is_some_and(|offset| {
            offset.get() < session.bytes.len() as u64
                && reknife::analysis::engine::off_to_va(
                    &session.bin,
                    reknife::analysis::engine::display_base(&session.bin),
                    offset.get(),
                ) == Some(string.address)
        })
    }));
    assert!(
        listing
            .strings(
                &session,
                &StringQuery {
                    text_contains: None,
                    referenced_only: false,
                    limit: Some(1),
                }
            )
            .len()
            <= 1
    );
    let pseudocode = listing.pseudocode(&session, function);
    assert!(!pseudocode.is_empty());

    let cfg = graph_api::query(
        &session,
        &GraphQuery {
            kind: GraphKind::ControlFlow,
            selector: function.name.clone(),
            maximum_nodes: None,
        },
    )
    .unwrap();
    assert_eq!(cfg.view.root, StaticVa(function.addr));
    assert_eq!(cfg.view.nodes.len(), function.blocks.len());
    let listing_addresses: std::collections::BTreeSet<_> = listing
        .function_lines_by_selector(&session, &function.name)
        .unwrap()
        .into_iter()
        .map(|line| line.address())
        .collect();
    assert!(cfg.view.nodes.iter().all(|node| node
        .instruction_addresses
        .iter()
        .all(|address| listing_addresses.contains(address))));
    assert!(cfg.dot.starts_with("digraph knife"));
    assert!(cfg.view.edges.iter().all(|edge| {
        cfg.view.nodes.iter().any(|node| node.id == edge.from)
            && cfg.view.nodes.iter().any(|node| node.id == edge.to)
    }));

    let calls = graph_api::query(
        &session,
        &GraphQuery {
            kind: GraphKind::CallClosure,
            selector: caller.name.clone(),
            maximum_nodes: Some(96),
        },
    )
    .unwrap();
    assert_eq!(calls.view.root, StaticVa(caller.addr));
    assert!(calls
        .view
        .nodes
        .iter()
        .any(|node| node.address == StaticVa(caller.addr)));
    let call_root = calls
        .view
        .nodes
        .iter()
        .find(|node| node.address == StaticVa(caller.addr))
        .unwrap();
    assert_eq!(call_root.byte_size, caller.size);
    assert_eq!(call_root.basic_blocks, caller.blocks.len());
    assert!(call_root.instruction_addresses.is_empty());
    assert_eq!(calls.view.edges.len(), caller.calls.len());

    let edit_address = StaticVa(function.addr);
    let receipt = apply_analyst_edit(
        &mut session,
        AnalystEdit::SetName {
            address: edit_address,
            name: "analyst_confirmed_entry".into(),
        },
    )
    .unwrap();
    assert_eq!(receipt.kind, AnalystEditKind::SetName);
    assert_eq!(receipt.address, Some(edit_address));
    assert_eq!(receipt.current.as_deref(), Some("analyst_confirmed_entry"));
    let stored = edit_address
        .get()
        .checked_sub(reknife::analysis::engine::display_base(&session.bin))
        .unwrap();
    assert_eq!(
        session.db.names.get(&stored).map(String::as_str),
        Some("analyst_confirmed_entry")
    );
    let prototype = apply_analyst_edit(
        &mut session,
        AnalystEdit::SetPrototype {
            function: edit_address,
            returns: "NTSTATUS".into(),
            params: vec!["void *".into(), "IRP *".into()],
        },
    )
    .unwrap();
    assert_eq!(prototype.kind, AnalystEditKind::SetPrototype);
    assert_eq!(
        prototype.current.as_deref(),
        Some("NTSTATUS (void *, IRP *)")
    );
    apply_analyst_edit(
        &mut session,
        AnalystEdit::SetField {
            type_name: "TEST_CONTEXT".into(),
            offset: 0x18,
            name: "fs_context".into(),
            data_type: Some("void *".into()),
        },
    )
    .unwrap();
    apply_analyst_edit(
        &mut session,
        AnalystEdit::BindType {
            function: edit_address,
            base: "rcx".into(),
            type_name: "TEST_CONTEXT".into(),
        },
    )
    .unwrap();
    apply_analyst_edit(
        &mut session,
        AnalystEdit::SetVariable {
            function: edit_address,
            base: "rcx".into(),
            name: "context".into(),
        },
    )
    .unwrap();
    assert_eq!(session.db.bound_type(stored, "rcx"), Some("TEST_CONTEXT"));
    assert_eq!(session.db.variable_name(stored, "rcx"), Some("context"));
    assert_eq!(
        session.db.field_name(stored, "rcx", 0x18),
        Some("fs_context")
    );
    let fields_before = session.db.fields.clone();
    assert!(apply_analyst_edit(
        &mut session,
        AnalystEdit::SetField {
            type_name: "TEST_CONTEXT".into(),
            offset: 0x20,
            name: "bad field".into(),
            data_type: None,
        }
    )
    .is_err());
    assert_eq!(session.db.fields, fields_before);
    assert_eq!(
        apply_analyst_edit(
            &mut session,
            AnalystEdit::ClearVariable {
                function: edit_address,
                base: "rcx".into(),
            },
        )
        .unwrap()
        .previous
        .as_deref(),
        Some("context")
    );
    assert_eq!(
        apply_analyst_edit(
            &mut session,
            AnalystEdit::ClearTypeBinding {
                function: edit_address,
                base: "rcx".into(),
            },
        )
        .unwrap()
        .previous
        .as_deref(),
        Some("TEST_CONTEXT")
    );
    assert_eq!(
        apply_analyst_edit(
            &mut session,
            AnalystEdit::ClearPrototype {
                function: edit_address,
            },
        )
        .unwrap()
        .previous
        .as_deref(),
        Some("NTSTATUS (void *, IRP *)")
    );
    assert_eq!(
        apply_analyst_edit(
            &mut session,
            AnalystEdit::ClearField {
                type_name: "TEST_CONTEXT".into(),
                offset: 0x18,
            },
        )
        .unwrap()
        .previous
        .as_deref(),
        Some("fs_context: void *")
    );
    assert!(apply_analyst_edit(
        &mut session,
        AnalystEdit::SetName {
            address: StaticVa(0),
            name: "must_not_wrap".into(),
        }
    )
    .is_err());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn binary_summary_preserves_container_address_kinds_and_existing_detail_facts() {
    let root = std::env::temp_dir().join(format!(
        "knife-summary-api-boundary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.exe");
    let database = root.join("fixture.json");
    std::fs::write(&target, reknife::formats::fixture::pe_with_iat_call()).unwrap();
    let session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "binary summary boundary test",
    )
    .unwrap();
    let summary = BinarySummary::from_session(&session);

    assert_eq!(summary.path, session.bin.path);
    assert_eq!(summary.image_base, StaticVa(session.bin.image_base));
    assert_eq!(
        summary.entry,
        ImageAddress::Rva(reknife::address::Rva(session.bin.entry))
    );
    assert!(summary
        .sections
        .iter()
        .all(|section| matches!(section.address, ImageAddress::Rva(_))));
    assert_eq!(summary.hashes.sha256, session.db.sha256);
    assert_eq!(summary.functions_recovered, session.an.functions.len());
    assert_eq!(summary.recovery_truncated, session.an.truncated);
    assert_eq!(
        summary.functions_named,
        session
            .an
            .functions
            .iter()
            .filter(|function| function.named)
            .count()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn linear_navigation_and_overview_keep_file_offsets_distinct_from_static_addresses() {
    let root = std::env::temp_dir().join(format!(
        "knife-linear-api-boundary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.exe");
    let database = root.join("fixture.json");
    let mut fixture = reknife::formats::fixture::pe_with_iat_call();
    fixture[reknife::formats::fixture::OPT + 0x18..reknife::formats::fixture::OPT + 0x20]
        .copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    std::fs::write(&target, fixture).unwrap();
    let session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "linear boundary test",
    )
    .unwrap();
    let listing = ListingIndex::from_session(&session);

    let raw_header = file_hex_window(
        &session.bin,
        &session.bytes,
        reknife::analysis::engine::display_base(&session.bin),
        FileHexQuery {
            file_offset: reknife::address::FileOffset(0),
            length: 32,
        },
    )
    .unwrap();
    assert_eq!(raw_header.start, reknife::address::FileOffset(0));
    assert_eq!(raw_header.rows.len(), 2);
    assert_eq!(
        raw_header.rows[0].file_offset,
        reknife::address::FileOffset(0)
    );
    assert!(
        raw_header.rows[0].mappings.is_empty(),
        "PE headers are raw file bytes, not an invented section mapping"
    );
    assert_eq!(raw_header.next, Some(reknife::address::FileOffset(32)));
    assert_eq!(raw_header.previous, None);
    assert!(file_hex_window(
        &session.bin,
        &session.bytes,
        reknife::analysis::engine::display_base(&session.bin),
        FileHexQuery {
            file_offset: reknife::address::FileOffset(u64::MAX),
            length: 16,
        },
    )
    .is_err());

    let first_function = StaticVa(session.an.functions.first().unwrap().addr);
    let hex_rows = listing
        .hex_window(
            &session,
            HexQuery {
                address: first_function,
                length: 32,
            },
        )
        .unwrap();
    assert_eq!(hex_rows.len(), 2);
    let first_function_offset = reknife::analysis::engine::va_to_off(
        &session.bin,
        reknife::analysis::engine::display_base(&session.bin),
        first_function.get(),
    )
    .unwrap() as u64;
    assert_eq!(hex_rows[0].file_offset.get(), first_function_offset);
    assert_eq!(hex_rows[1].file_offset.get(), first_function_offset + 16);
    assert_eq!(hex_rows[0].address, first_function);
    assert_eq!(hex_rows[1].address.get(), first_function.get() + 16);
    assert_eq!(hex_rows[0].byte_length, 16);

    let text = session
        .bin
        .sections
        .iter()
        .find(|section| section.name == ".text")
        .unwrap();
    let tail_length = 8_u64.min(text.file_size);
    let text_tail = StaticVa(
        reknife::analysis::engine::display_base(&session.bin) + text.vaddr + text.file_size
            - tail_length,
    );
    let tail_rows = listing
        .hex_window(
            &session,
            HexQuery {
                address: text_tail,
                length: 32,
            },
        )
        .unwrap();
    assert_eq!(tail_rows.len(), 1);
    assert_eq!(tail_rows[0].address, text_tail);
    assert_eq!(
        tail_rows[0].file_offset.get(),
        text.file_off + text.file_size - tail_length
    );
    assert_eq!(tail_rows[0].byte_length, tail_length);
    assert!(listing
        .hex_window(
            &session,
            HexQuery {
                address: StaticVa(u64::MAX),
                length: 16,
            },
        )
        .is_err());

    let first = listing
        .linear(
            &session,
            &LinearQuery {
                file_offset: None,
                address: None,
                maximum_rows: 4,
            },
        )
        .unwrap();
    assert_eq!(first.start, reknife::address::FileOffset(0));
    assert!(matches!(
        first.rows.first(),
        Some(LinearRow::Region { file_offset, .. })
            if *file_offset == reknife::address::FileOffset(0)
    ));
    assert!(first.rows.iter().any(|row| matches!(
        row,
        LinearRow::Data {
            location: LinearLocation::FileOffset(_),
            ..
        }
    )));
    let continuation = first.next.expect("small window has a continuation");
    let second = listing
        .linear(
            &session,
            &LinearQuery {
                file_offset: Some(continuation),
                address: None,
                maximum_rows: 4,
            },
        )
        .unwrap();
    assert_eq!(second.start, continuation);

    let function = session.an.functions.first().unwrap();
    let at_function = listing
        .linear(
            &session,
            &LinearQuery {
                file_offset: None,
                address: Some(StaticVa(function.addr)),
                maximum_rows: 16,
            },
        )
        .unwrap();
    assert!(at_function.rows.iter().any(|row| matches!(
        row,
        LinearRow::Instruction { address, .. } if *address == StaticVa(function.addr)
    )));
    assert!(listing
        .linear(
            &session,
            &LinearQuery {
                file_offset: None,
                address: Some(StaticVa(u64::MAX)),
                maximum_rows: 1,
            },
        )
        .is_err());

    let signals = vec![reknife::api::risk_signals::RiskSignal {
        address: StaticVa(function.addr),
        function: Some(function.name.clone()),
        api: "test_api".into(),
        pattern: "boundary-signal".into(),
        severity: 2,
        detail: "unresolved test signal".into(),
        reachability: reknife::analysis::reachability::Reachability::Unresolved,
        source: "HEURISTIC".into(),
        trail: Vec::new(),
    }];
    let overview = listing.overview(&session, 64, &signals);
    assert_eq!(overview.size, session.bytes.len() as u64);
    assert!(!overview.buckets.is_empty());
    assert_eq!(
        overview.buckets[0].file_offset,
        reknife::address::FileOffset(0)
    );
    assert_eq!(
        overview
            .buckets
            .iter()
            .map(|bucket| bucket.risk_signals as usize)
            .sum::<usize>(),
        signals.len()
    );
    assert!(overview
        .buckets
        .iter()
        .any(|bucket| bucket.risk_signals == 1 && bucket.maximum_severity == 2));
    assert!(overview.entry_bucket.is_some());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn symbol_queries_preserve_import_identity_references_filtering_and_limits() {
    let root = std::env::temp_dir().join(format!(
        "knife-symbol-api-boundary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.exe");
    let database = root.join("fixture.json");
    std::fs::write(&target, reknife::formats::fixture::pe_with_iat_call()).unwrap();
    let session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "symbol boundary test",
    )
    .unwrap();

    let imports = symbol_api::imports(&session, &SymbolQuery::default());
    assert!(!imports.is_empty());
    assert!(imports.iter().all(|symbol| symbol.address.is_some()));
    assert!(imports.iter().all(|symbol| {
        let address = symbol.address.unwrap().get();
        symbol.reference_count == session.an.xrefs_to.get(&address).map_or(0, Vec::len)
    }));
    let mut identities = std::collections::BTreeSet::new();
    assert!(imports
        .iter()
        .all(|symbol| identities.insert((symbol.module.clone(), symbol.name.clone()))));

    let selected = &imports[0];
    let filtered = symbol_api::imports(
        &session,
        &SymbolQuery {
            text_contains: Some(selected.name.to_uppercase()),
            limit: None,
        },
    );
    assert!(filtered
        .iter()
        .any(|symbol| { symbol.module == selected.module && symbol.name == selected.name }));
    assert_eq!(
        symbol_api::imports(
            &session,
            &SymbolQuery {
                text_contains: None,
                limit: Some(1),
            },
        )
        .len(),
        1
    );
    let exports = symbol_api::exports(&session, &SymbolQuery::default());
    assert_eq!(exports.len(), session.bin.exports.len());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn risk_signals_never_turn_missing_direct_proof_into_unreachability() {
    let root = std::env::temp_dir().join(format!(
        "knife-risk-signal-api-boundary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.sys");
    let database = root.join("fixture.json");
    std::fs::write(&target, reknife::formats::fixture::pe_with_driver()).unwrap();
    let session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "risk signal boundary test",
    )
    .unwrap();
    let signals = risk_signals::query(&session);
    assert!(signals.iter().all(|signal| {
        signal.reachable_compat()
            || signal.reachability == reknife::analysis::reachability::Reachability::Unresolved
    }));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn driver_surface_preserves_unresolved_reachability() {
    let root = std::env::temp_dir().join(format!(
        "knife-driver-api-boundary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.sys");
    let database = root.join("fixture.json");
    std::fs::write(&target, reknife::formats::fixture::pe_with_driver()).unwrap();
    let session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "driver surface boundary test",
    )
    .unwrap();
    let listing = ListingIndex::from_session(&session);
    let surface = listing
        .driver_surface(&session)
        .expect("fixture is a driver");
    assert!(surface.is_driver);
    let dispatch = surface
        .indirect_dispatch
        .iter()
        .find(|edge| edge.table_offset == 0xe0)
        .expect("MajorFunction[14] indirect edge");
    assert_eq!(dispatch.pointer_value, Some(PointerValue(0x1100)));
    assert_eq!(dispatch.target, Some(StaticVa(0x1100)));
    assert_eq!(dispatch.loader, StaticVa(0x102b));
    assert_eq!(dispatch.table_address, None);
    assert_eq!(dispatch.caller, None);
    assert_eq!(dispatch.guarded_call_wrapper, None);
    assert_eq!(
        dispatch.reachability,
        reknife::analysis::reachability::Reachability::ConfirmedIndirect
    );
    assert!(surface.primitives.iter().all(|primitive| {
        primitive.reachable
            == matches!(
                primitive.reachability,
                reknife::analysis::reachability::Reachability::ConfirmedDirect
                    | reknife::analysis::reachability::Reachability::ConfirmedIndirect
            )
    }));
    assert!(surface.primitives.iter().all(|primitive| {
        primitive.reachable
            || primitive.reachability == reknife::analysis::reachability::Reachability::Unresolved
    }));
    let confirmed = surface.filtered(DriverSurfaceQuery {
        minimum_severity: 1,
        confirmed_reachable_only: true,
    });
    assert!(confirmed
        .primitives
        .iter()
        .all(|primitive| primitive.reachability.is_confirmed()));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn staged_patches_update_and_restore_the_live_workspace_image() {
    let root = std::env::temp_dir().join(format!(
        "knife-patch-api-boundary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.exe");
    let database = root.join("fixture.json");
    std::fs::write(&target, reknife::formats::fixture::pe_with_iat_call()).unwrap();
    let mut session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "patch boundary test",
    )
    .unwrap();
    let address = StaticVa(session.an.functions[0].addr);
    let offset = reknife::analysis::engine::va_to_off(
        &session.bin,
        reknife::analysis::engine::display_base(&session.bin),
        address.get(),
    )
    .unwrap();
    let original = session.bytes[offset];
    let replacement = original ^ 1;

    let receipt = patches::stage_patch(&mut session, address, vec![replacement]).unwrap();
    assert_eq!(receipt.original, vec![original]);
    assert_eq!(receipt.replacement, vec![replacement]);
    assert_eq!(session.bytes[offset], replacement);
    assert_eq!(patches::patches(&session).len(), 1);

    let exported = root.join("patched.exe");
    let export = patches::export_workspace_image(&session, &exported).unwrap();
    assert_eq!(export.bytes_written, session.bytes.len());
    assert_eq!(std::fs::read(&exported).unwrap()[offset], replacement);
    assert!(patches::export_workspace_image(&session, &target).is_err());

    let cleared = patches::clear_patch(&mut session, receipt.file_offset).unwrap();
    assert_eq!(cleared.restored, vec![original]);
    assert_eq!(session.bytes[offset], original);
    assert!(patches::patches(&session).is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn analyst_facts_and_type_libraries_cross_only_the_typed_facade() {
    let root = std::env::temp_dir().join(format!(
        "knife-facts-api-boundary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.exe");
    let database = root.join("fixture.json");
    let library = root.join("types.json");
    std::fs::write(&target, reknife::formats::fixture::pe_with_iat_call()).unwrap();
    let mut session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        200_000,
        "facts boundary test",
    )
    .unwrap();
    let function = StaticVa(session.an.functions[0].addr);
    apply_analyst_edit(
        &mut session,
        AnalystEdit::SetField {
            type_name: "BOUNDARY_CONTEXT".into(),
            offset: 0x18,
            name: "length".into(),
            data_type: Some("size_t".into()),
        },
    )
    .unwrap();
    apply_analyst_edit(
        &mut session,
        AnalystEdit::BindType {
            function,
            base: "rcx".into(),
            type_name: "BOUNDARY_CONTEXT".into(),
        },
    )
    .unwrap();
    apply_analyst_edit(
        &mut session,
        AnalystEdit::SetVariable {
            function,
            base: "rcx".into(),
            name: "context".into(),
        },
    )
    .unwrap();

    let rows = facts::analyst_facts(&session, &FactQuery::default());
    assert!(rows.iter().any(|row| row.kind == FactKind::Structure));
    assert!(rows.iter().any(|row| row.kind == FactKind::Binding));
    assert!(rows.iter().any(|row| row.kind == FactKind::Variable));
    let filtered = facts::analyst_facts(
        &session,
        &FactQuery {
            text_contains: Some("length".into()),
        },
    );
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].kind, FactKind::Structure);
    let action = facts::line_actions(&session, function, "context->length = 1;").unwrap();
    let field = action.field.unwrap();
    assert_eq!(field.base, "rcx");
    assert_eq!(field.offset, 0x18);

    let exported = facts::export_type_library(&session, &library).unwrap();
    assert_eq!(exported.operation, TypeLibraryOperation::Export);
    assert_eq!((exported.types, exported.fields), (1, 1));
    let destination_database = root.join("destination.json");
    let mut destination = Session::open(
        target.to_str().unwrap(),
        destination_database.to_str(),
        200_000,
        "facts import test",
    )
    .unwrap();
    let imported = facts::import_type_library(&mut destination, &library, false).unwrap();
    assert_eq!(imported.operation, TypeLibraryOperation::ImportMerge);
    assert_eq!((imported.types, imported.fields), (1, 1));
    assert!(facts::analyst_facts(&destination, &FactQuery::default())
        .iter()
        .any(|row| row.name == "BOUNDARY_CONTEXT"));
    let _ = std::fs::remove_dir_all(root);
}
