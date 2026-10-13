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

Primary references:

- https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build
- https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GettingStarted.md
- https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md
