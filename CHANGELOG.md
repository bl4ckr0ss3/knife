# Changelog

## v1.0.0

First public release.

- Multi-format parsing: PE, ELF, Mach-O (via goblin)
- Static triage with a transparent, additive verdict
- Sections with per-section entropy, imports, exports, capability detection
- Strings (ASCII + UTF-16), defanged IOC extraction
- Hashes: MD5 / SHA-1 / SHA-256 and imphash
- Whole-file entropy map
- Crypto / packer / embedded-format constant scanner (`scan`)
- YARA matching via yara-x (`yara`, `--rules`)
- Analysis engine: function recovery, control-flow graph, cross-references
  (`funcs`, `dis --func`)
- x86/x64 disassembly via iced-x86
- `--json` output on every analysis command
- Cross-platform CI; prebuilt release binaries for Linux, macOS, Windows
