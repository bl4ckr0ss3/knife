# External analysis providers

Knife's native engine remains the deterministic baseline. Optional providers
add independent evidence and deeper specialist engines without making them a
hard dependency or allowing arbitrary shell commands through MCP.

## Provider contract

- Providers are discoverable through `provider_status`, including version,
  executable, license, safety mode, operations, and an unavailability reason.
- Every provider operation declares the same access class, target requirement,
  result mode, and evidence behavior as a native Knife operation.
- Static providers never execute the target. Future debugger providers must use
  `target_execution` and the corresponding approval policy.
- Arguments are typed and converted to fixed provider commands. Knife does not
  expose an arbitrary command or script escape.
- Child stdin is closed, output is drained with a hard bound, and the process is
  killed at a deadline. Oversized, timed-out, malformed, or non-JSON results are
  errors, not partial evidence.
- Providers analyze a private temporary snapshot of the exact workspace bytes
  identified by Knife, including staged patches. The original target is never
  handed out as mutable state and the snapshot is removed after each call.
- Provider conclusions state their engine and limitations. Agreement between
  engines raises confidence; it still does not prove runtime behavior.

## Implemented: Rizin

The Rizin provider invokes a separately installed `rizin` executable in static,
out-of-process mode. Set `KNIFE_RIZIN` to an explicit executable path when it is
not on `PATH`. Rizin's JSON output is documented by its project, and its core is
LGPL-3.0-only; Knife does not link or redistribute it.

The first provider surface covers binary metadata, sections, imports, exports,
symbols, strings, entrypoints, libraries, relocations, classes, functions,
function details, structured disassembly, xrefs, CFGs, and the global call graph.
Collection results use Knife's query-scoped pagination. Automatic analysis has a
30-second process deadline and each output stream has an 8 MiB retention bound.
Each uncached call uses an isolated process. Raw structured results are cached by
workspace digest, provider executable identity, and fixed command in a bounded
16-item/32-MiB LRU, so continuation pages and repeated questions do not rerun
automatic analysis.

Sources:

- Rizin repository and license: <https://github.com/rizinorg/rizin>
- Rizin JSON API conventions: <https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md#json>

## Implemented: YARA-X

Knife pins YARA-X 1.12 and its companion crates because it is the newest
release family compatible with Knife's Rust 1.88 minimum. `yarax_validate_rules`
is target-free and returns compiler warnings plus a paginated inventory without
retaining rule source. `yarax_scan` and `yarax_scan_range` operate directly on
the immutable workspace bytes, cap rule source at 256 KiB, cap per-pattern
matches, expose a scan timeout, truncate match previews to 64 bytes, and
preserve file offsets separately from mapped static addresses. Evidence records
include the ruleset and normalized full-result digests and state that behavioral
meaning comes from the supplied rule rather than from the matching engine
itself. A result is marked partial when pagination remains or a pattern may have
hit the configured match cap.

Source and license: <https://github.com/VirusTotal/yara-x/tree/v1.12.0>

## Researched provider queue

Ghidra exposes `ghidra_functions` and `ghidra_decompile` for PE/ELF through shared
CLI/MCP/TUI contracts. Configure `KNIFE_GHIDRA_HEADLESS`, a matching JDK, and
`KNIFE_GHIDRA_WORK_ROOT` (an existing disk-backed non-hidden path). Inventory
pages contain at most 400 rows; the cached inventory is capped at 20,000 entries
and reports incomplete coverage explicitly. Decompilation requires the
`provider_static_address` returned by Ghidra, not Knife's correlated address.
Reports preserve file offsets, analysis timeouts, failures, workspace hashes
and inferred pseudocode. Engine-version probing remains unfinished. Cached
continuations require the same analysis timeout; expired reports must restart.
The process adapter has been live-tested, but the newly registered MCP workflow
still needs real-server dogfooding.

The initial standalone capa adapter exposes `capa_capabilities` for PE/ELF.
Set `KNIFE_CAPA` to its executable or install it on PATH. It uses fixed JSON
arguments, verifies the report's sample SHA-256 against workspace bytes, and
caches reports in an eight-item/32-MiB LRU for stable continuation. Each process
has a default 30-second deadline (`timeout_seconds` accepts 1–120) and an
8-MiB output bound. Unix provider deadlines terminate the process group,
including packaged-engine helpers that could otherwise keep output pipes open.
Rule metadata includes ATT&CK
and MBC fields; top-level match locations keep capa's declared address types.
Live MCP validation is documented in [capa-field-validation.md](capa-field-validation.md).
`capa_rule_matches` exposes matched rule source and supporting trees from the
same cached report. Match pages contain at most 20 entries, each bounded to 512
nodes and depth 16, with explicit truncation markers. Native match locations
can be followed through evidence navigation; managed tokens retain their own
address kinds. Live validation of this deeper view remains outstanding.

| provider | integration | value | policy |
|---|---|---|---|
| capa | standalone JSON process first; Python library adapter later | capability rules for PE, ELF, .NET, shellcode, and sandbox reports | Apache-2.0; static/read-only; rules and engine versions recorded |
| YARA-X | implemented native Rust provider | bounded inline rule validation plus workspace/range scans with match offsets, metadata, and scan timeout | BSD-3-Clause; static/read-only; ruleset digest recorded |
| Ghidra | headless project and scripts in an isolated provider workspace | mature multi-architecture analysis, decompilation, types, p-code, references | Apache-2.0 core; static/read-only until explicit project-write operations exist |
| GDB / LLDB | persistent debugger provider process | launch/attach, modules, registers, memory, breakpoints, stepping, events | always `target_execution`; never enabled by static-analysis calls |
| WABT / Binaryen | bounded subprocesses, then native adapters where justified | WASM validation, WAT, CFG and optimization-aware inspection | static/read-only; tool version and transformation flags recorded |

Primary references:

- capa library/standalone installation: <https://github.com/mandiant/capa/blob/master/doc/installation.md>
- capa JSON consumption: <https://github.com/mandiant/capa/blob/master/doc/usage.md#ways-to-consume-capa-output>
- YARA-X Rust implementation and license: <https://github.com/VirusTotal/yara-x>
- YARA-X scanner and custom modules: <https://github.com/VirusTotal/yara-x/blob/main/docs/ModuleDeveloperGuide.md>
- Ghidra headless analyzer: <https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md>
- Ghidra licensing: <https://github.com/NationalSecurityAgency/ghidra/blob/master/NOTICE>

## Expansion rule

The target of 100–120 tools is a capability target, not a wrapper target. A new
operation must answer a distinct investigation question, declare its policy,
bound its result, preserve address spaces, and carry evidence or a documented
reason why evidence is not applicable. Aliases do not count toward the target.
