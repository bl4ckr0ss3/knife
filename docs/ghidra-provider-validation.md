# Ghidra integration validation

## Prerequisites verified

Portable dependencies were fetched into a disk-backed validation cache, without
installing system packages or changing shell configuration.

- Ghidra: 12.1.4 PUBLIC, official `Ghidra_12.1.4_build` release.
- Archive SHA-256: `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`.
- JDK: Temurin 21.0.12.1+1, matching the release-specific JDK 21 requirement.
- JDK archive SHA-256: `ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94`.
- `java -version` confirmed the portable runtime.
- `analyzeHeadless` reached its documented usage screen. Its exit status 1 was
  expected because no project arguments were supplied; no target was analyzed.

Local validation directory:
`/home/chixin/.cache/knife-validation/ghidra-check.yJs735`.

The host has limited RAM and nearly full swap. `/tmp` is memory-backed and must
not hold the Ghidra distribution or its project files. Headless 12.1.4 supports
`GHIDRA_HEADLESS_MAXMEM`; use a bounded heap and `-max-cpu 1` for initial tests.

## Required implementation and verification

1. A Knife-owned headless exporter for function inventory and decompilation.
2. Isolated disk-backed project and script directories, exact workspace input,
   bounded stdout, process deadline, analysis timeout and process-tree cleanup.
3. Explicit analysis-timeout and decompilation-failure reporting.
4. Typed static/file locations and content/version identity in evidence.
5. Stable report caching and query-scoped pagination.
6. Fixture tests followed by an actual MCP investigation on a real target.

These prerequisite checks do not establish a working Knife Ghidra provider.

## Exporter validation

Knife's `src/providers/ghidra/KnifeExport.java` compiled through Ghidra's script
loader and ran against `/usr/bin/true` in read-only import mode. With a 512-MiB
heap, one analysis CPU and a 60-second analysis deadline:

- Function export returned total 134, a requested five-row inventory, and
  explicit `truncated: true` / `analysis_timed_out: false`.
- Decompilation at Ghidra address `0x102000` returned `_DT_INIT`, size 27,
  `decompile_completed: true`, and untruncated pseudocode.
- Ghidra discarded the imported file because `-readOnly` was requested.
- The first project location under `.cache` was rejected: Ghidra project paths
  cannot contain a component beginning with `.`. The validated project root was
  `/home/chixin/Desktop/Tools/knife-ghidra-project.yJhxwN`.
- Ghidra loaded this ELF at image base `0x100000`. Provider addresses must be
  preserved and explicitly correlated with Knife's image before navigation.

The Rust/MCP adapter, input snapshots, address correlation and report caching
remain to be implemented. These runs validate the exporter, not end-to-end MCP.

## File-backed correlation boundary

The exporter now includes the address-space name and nullable source file
offset for each function entry. A second live read-only export on `/usr/bin/true`
returned `_DT_INIT` at provider address `0x102000`, address space `ram`, file
offset 8192, and the next function at `0x102020` / file offset 8224. Analysis
completed without a timeout and reported 134 functions.

The Rust boundary parses the fixed logger record, validates schema/provider and
timeout status, and rejects duplicate records or unexpected trailing content.
It correlates source offsets with Knife's file-backed sections using checked
arithmetic, rather than assuming loader image bases agree. Missing, out-of-file,
or unmapped offsets remain unknown. This boundary is not yet an advertised MCP
provider; process orchestration and end-to-end evidence integration remain open.
Pseudocode truncation also avoids splitting a UTF-16 surrogate pair.

## Process adapter under validation

The Rust `export` entry point now materializes the compiled-in exporter into an
exclusively created private project directory, imports exact workspace bytes,
and uses the shared bounded process runner. It fixes the heap at 512 MiB and
analysis CPU count at one, accepts only typed inventory/decompile requests,
and attaches workspace SHA-256 plus `target_execution: false` to the report.
The exporter reports Ghidra's imported executable SHA-256; the adapter rejects
results unless it matches the workspace hash. The input snapshot also lives in
the private disk-backed project, rather than the host's temporary filesystem.
Project cleanup owns only the newly created directory. Unix deadlines terminate
the process group; Windows descendant cleanup is still a shared-runner limitation.

Configuration: `KNIFE_GHIDRA_HEADLESS` names the launcher;
`KNIFE_GHIDRA_WORK_ROOT` names an existing disk-backed directory with no hidden
path components. Java remains supplied through the launch environment.
The ignored `live_isolated_function_export` test additionally requires
`KNIFE_GHIDRA_TEST_TARGET`. It passed against `/usr/bin/true` through the actual
Rust process adapter in 23.53 seconds, including imported sample identity and
file-backed function checks. Four boundary/request regressions also passed.
MCP registration, report caching, pagination and evidence envelopes are still
outstanding; this is not yet an end-to-end agent investigation.

Primary references:

- https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build
- https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GettingStarted.md
- https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md
