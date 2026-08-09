# Changelog

## Unreleased

- `pseudo`: a decompiler engine built on a typed IR. It lifts each instruction,
  propagates expressions, eliminates dead stores with a whole-function liveness
  pass, and folds constants, so a call renders with its recovered arguments
  (`lstrcpyA(&(ebp - 0x28), *(ebp+8) + 0x1c)`) and the noise around it is gone.
  Control flow reads as `if`/`goto` (structuring is a later phase); unmodelled
  instructions are shown verbatim rather than guessed at.
- The engine no longer re-decodes shared block tails, so analysis of real
  binaries is complete rather than budget-truncated (EQNEDT32.EXE: 537 to 930
  functions), and the budget is raised so normal targets finish.
- `audit` reads 32-bit stack-passed arguments, which is what lets knife land on
  CVE-2017-11882.
- `audit` reads the copy source, not just the destination: a copy from a
  constant string is no longer flagged as a stack overflow.
- `audit` provenance follows values into predecessor blocks (bounded depth), so
  a value set by an earlier block and used by a common tail is resolved.
- `audit` understands the 32-bit stack calling convention: arguments passed by
  `push` are recovered, so legacy 32-bit binaries are analysed properly. This is
  what lets knife land on CVE-2017-11882 in `EQNEDT32.EXE`.
- A single shared analysis budget, so a site `audit` finds can always be shown
  by `dis --func`.
- Added a case study reproducing CVE-2017-11882 with knife (`docs/`).

## v1.4.0

- ELF function discovery from `.eh_frame_hdr`, the Linux counterpart to the PE
  exception directory.
- Hardening: never panics on a malformed file. A torture harness fuzzes the
  whole pipeline on every build; the parser catches even a dependency panic.
- `audit` precision: a clamped (`cmp`+`cmov`) or masked (`and`) size is ranked
  likely-safe instead of high; a copy into a stack buffer is flagged as a stack
  overflow, reading the destination as well as the length.

## v1.3.0

- Function discovery from the PE exception directory (`.pdata`), recovering the
  code a stripped C++ binary reaches only through indirect calls. On `7z.dll`
  this is the difference between 87 functions and 6472.

## v1.2.0

- `audit`: argument-provenance bug finder that ranks sink call sites by how
  exploitable their arguments look.
- AArch64 disassembly and PLT-veneer resolution.
- FLIRT-lite library-function identification.
- Data cross-references, string annotations in the listing, a hex view in the TUI.

## v1.1.0

- Exploit-mitigation audit (`sec`), attack-surface sinks (`sinks`),
  cross-references (`xrefs`), call-graph reachability (`paths`).
- Persistent analysis database: names and notes kept between sessions
  (`name`, `note`, `db`), keyed by file hash.
- Interactive TUI (`tui`): function list, listing, cross-references, naming.
- IAT and PLT import-name resolution in disassembly.

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
