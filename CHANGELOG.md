# Changelog

## Unreleased

- Bulk output is buffered. `println!` flushes on every newline, which is one
  write syscall per line; `strings`, `funcs`, and `dis` now share one buffer.
  `knife strings` on a 327 MB DLL (2.3 million literals) goes from 26.1s to
  3.9s, and a closed pipe (`knife strings big.dll | head`) exits cleanly
  instead of panicking.
- Function recovery is about 30% faster. Cross-references were recorded into a
  `BTreeMap<u64, Vec<_>>` as they were found, which costs a tree descent per
  reference and a heap allocation for every address seen for the first time.
  They are now collected flat and grouped once: on a 25 MB DLL with 1.1 million
  references, recovery drops from 3.39s to 2.39s.
- Instructions cost less memory. The raw bytes are held inline rather than in a
  `Vec` per instruction, and the resolved target name is boxed: 88 bytes plus an
  allocation each becomes 64 bytes and none. Peak memory analysing a 25 MB DLL
  falls from 1084 MB to 827 MB. Two whole-image copies are gone as well: one
  made even when a target had no staged patches, and one the interactive view
  made to hand the binary to its analysis thread.
- `pseudo`: an indirect call whose target cannot be resolved reads as
  `(*rax)(...)` or `(*(rcx + 0x18))(...)`. It used to render as `sub()`, which
  looks like a call to a function named `sub` — the prefix Knife gives every
  function it recovers without a symbol.
- `tui`: the left pane grows with the terminal instead of staying at 38
  columns, and the attack-surface and function rows take their column widths
  from the pane they are drawn into, so the containing function is no longer
  cut short on every row.
- The analysis cache is schema 2, for the instruction layout above. An older
  cache is recomputed rather than read.
- Dropped the unused `memmap2` dependency.
- The README animation is rendered, not captured: `--features record` builds a
  recorder that drives the real interface off-screen through a scripted session
  (`scripts/demo.knife`) and writes frames an off-line rasterizer paints, so it
  rebuilds deterministically and carries no console artifacts.
- Tests: the mutation walks are one test per fixture, so the harness runs them
  in parallel, and the full pipeline runs behind every mutation in a file's
  structured prefix and every sixteenth offset after it. Every offset is still
  parsed, which is where an unbounded structure read shows up. The suite's
  slowest group goes from 623s to 136s.

## v1.6.0

- `drv`: kernel-driver and BYOVD analysis (`knife drv FILE`). Reads identity
  (publisher, version info, Authenticode signature state), the devices and
  symbolic links it exposes, IRP dispatch handlers, the IOCTL surface, and the
  kernel primitives each handler reaches. `--reachable` keeps only what
  user-mode code can actually drive, so accidental surface does not inflate the
  report. A persistence scanner pulls the Authenticode chain out of the
  certificate table; a bundled snapshot of the loldrivers project
  (`data/loldrivers.json`) flags matching known-vulnerable samples by SHA-256;
  and Windows kernel export ordinal imports are resolved from a generated table
  when `ntoskrnl` symbols are stripped.
- `patch`, `graph`, `typelib`, `var`, `proto`: a persistent analyst workspace.
  Binary edits are staged non-destructively (`knife patch --bytes/--clear/
  --export`) and replay through every command, then export atomically; user
  structure layouts import/export between binaries (`typelib`); and
  function-scoped pseudocode variable and prototype overrides round-trip
  through the database. The TUI edits all of it in place.
- `graph FUNC --dot`: one function's control-flow graph as deterministic text,
  JSON, or Graphviz, stable ordering and DOT-escaped symbols.
- Versioned persistent per-target analysis cache: the second pass over a binary
  is warm for every command, and the key is the file hash + names digest so your
  analyst facts always invalidate it.
- C++ / MSVC / Rust demangling for recovered function names.
- `diff`: compares two binaries' functions, imports, and sections and exits 1
  on any change.
- `mcp`: a Model Context Protocol server (`knife mcp`), a JSON-RPC 2.0 stream over
  stdio that exposes the analysis as agent tools: `list_functions`, `disassemble`,
  `decompile`, `audit`, `xrefs`, `info`. It reuses the same engine, decompiler,
  and audit as the CLI, and caches the last-analysed file so repeated calls on one
  target do not re-run the engine. This is what lets an agent drive knife directly.
- `tui`: callees. `x` toggles the reference pane between callers (xrefs to what
  is under the cursor) and callees (the calls the current function makes), so the
  call graph is navigable both directions; `↵` jumps either way.
- `pseudo`: conditional idioms. `setcc` reads as the boolean it computes
  (`al = ecx == edx`) and `cmovcc` as a ternary (`rax = rax == rbx ? rcx : rax`),
  so neither shows up as an opaque `asm(...)` any more.
- `pseudo`: string literals inline. A pointer to a string, whether an x64
  `lea reg, [rip + s]` or a 32-bit `push offset s`, reads as the quoted text
  (`lstrcpyA(&var_28, "Times New Roman")`) instead of a bare address, so the data
  the code touches is visible in the decompilation.
- `pseudo`: x64 stack frames. A function without a frame pointer (the common x64
  case) now gets named locals and arguments too: the stack pointer is tracked
  through the prologue and across blocks, and the registers that alias it (MSVC's
  `mov rax, rsp`) are followed, so `[rsp + 0x30]` reads `arg_8` and a spill slot
  reads `var_8`. The frame-base copy, the frame allocation, and the callee-saved
  register spills and restores are dropped as the pure bookkeeping they are.
- `tui`: a sinks pane. `s` toggles the left pane between the function list and
  the ranked attack surface (the argument-provenance audit, most severe first);
  `↵` on a sink jumps straight to its call site in the listing. This puts the
  whole find-the-sink loop inside the interactive view.
- `tui`: in-listing search. When the listing is focused, `/` searches the code
  (disassembly or pseudocode) instead of filtering the function list; `/`↵
  repeats, jumping to the next match and wrapping.
- `pseudo`: self-updating assignments read as compound operators, so a counter
  is `ecx--` and an accumulate is `x += 0x10` rather than restating the target.
- `pseudo`: global naming. A fixed-address memory operand (an absolute or
  RIP-relative access) reads as its symbol name when the engine knows one and
  `g_<addr>` otherwise, so `*(0x45519c)` becomes `g_45519c` and a struct field
  through a global pointer reads `*(g_4641d4 + 0xb2)` instead of nested
  dereferences of a bare number.
- Robustness: the decompiler now bounds expression propagation so no hostile
  file can drive a stack overflow through `pseudo`, the torture harness
  exercises the decompiler itself, runtime MCP frames are capped, each MCP
  request is contained against panics, `hex`/`dis`/`db` reject or survive
  overflowing and mutually-exclusive inputs, and the stats-performance fix
  makes device-string scan linear.
- The experimental native GUI and its dependencies are removed from the
  release; the crate ships the CLI/TUI/MCP only.

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
