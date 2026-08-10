# Changelog

## v1.5.0

- `tui`: the listing pane toggles to decompiled pseudocode with `d`, so the
  structured `if`/`else`/`while`/`switch` view is available interactively next to
  the disassembly. It follows the selected function as you navigate, keywords are
  highlighted, and the pane title shows the row position in long listings.
- `pseudo`: a decompiler engine built on a typed IR. It lifts each instruction,
  propagates expressions, eliminates dead stores with a whole-function liveness
  pass, and folds constants, so a call renders with its recovered arguments and
  the noise around it is gone.
- `pseudo`: cross-block propagation is a proper dataflow fixpoint. Each block is
  lifted from the meet of its predecessors' exit states, iterated in reverse
  postorder until stable, so values flow through forward edges, joins, and back
  edges. The meet is the SSA merge rule: a value survives a join only when every
  incoming path agrees on it, never a guess.
- `pseudo`: control-flow structuring. Dominators and post-dominators drive a
  recursive emitter that rebuilds nested `if`/`else` and `while` from the graph,
  so output reads as C rather than a goto chain. The few edges that break
  nesting (shared `switch` tails, a jump into a common handler) become an
  explicit `goto` to a labelled block, so the flow is preserved exactly rather
  than approximated. There is no type recovery, and an unmodelled instruction is
  shown verbatim rather than guessed at.
- `pseudo`: `switch` recovery. An indexed jump through a table is rendered as a
  `switch` on the selector, with each case body structured and grouped when
  several indices share a target. The engine already resolves the table's case
  edges; the decompiler now uses them, so a function built around a jump table
  reads as a switch instead of collapsing to a flat goto listing (EQNEDT32.EXE
  has 51 such functions).
- `pseudo`: condition recovery. A conditional jump reads the comparison the last
  flag-setting instruction expressed, including the arithmetic and logic ops
  (`dec`, `sub`, `and`, ...) that set flags without a `cmp`, so `dec ecx; jnz`
  reads `ecx != 0` instead of an opaque `flags` test. The compare is carried
  across blocks by the same dataflow, so a `cmp` shared by several conditional
  jumps (a multi-way dispatch) is recovered at each branch, and it is dropped the
  moment an instruction clobbers the flags, so a stale compare is never used.
  Unsigned conditions that a "result vs zero" test cannot express fall back to
  the raw condition rather than a wrong comparison.
- `pseudo`: bottom-tested loops. A loop whose header does work on each iteration
  (a counter decrement, a value read in the condition) keeps that work inside the
  loop and leaves on the exit edge, so a `do`/`while` reads faithfully instead of
  hoisting the body out.
- `pseudo`: stack-frame analysis. In a frame-pointer function, `[ebp - 0x28]`
  becomes the named local `var_28` and `[ebp + 8]` the argument `arg_8`, so the
  same slot reads the same way everywhere. The frame bookkeeping (`mov ebp,esp`,
  the `sub esp`/`add esp` allocation and cleanup, `push ebp`, `leave`) is
  dropped, and the stack and frame pointers are no longer propagated, which fixes
  an `[ebp + k]` that could render as a stale `[esp + k]`. The CVE-2017-11882
  overflow now reads as `lstrcpyA(&var_28, arg_8 + 0x1c);`.
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
