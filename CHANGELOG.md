# Changelog

## Unreleased

- Every agent tool call is appended to `<project>.agentlog.jsonl` beside the
  workspace database — timestamp, tool name, bounded arguments, and the first
  static address — so a complete investigation stays auditable after the run.
- The evidence contract now forbids fake unknowns: a value an available tool
  can determine must be read and reported, and `unknown` is reserved for what
  no available tool can resolve. Quick triage prompts say the same.
- Tool-call budgets grew from 24 to 48 per investigation: local analysis calls
  cost milliseconds while model rounds cost a provider request, so deep
  analyses stop dying at the budget before finishing their reads.
- Streamed model replies are now shown live in the activity line — a tail of
  the visible reply, the provider's reasoning stream when one is sent, and
  `Preparing tool call: <name>` as fragments arrive — instead of a silent
  byte counter.

- Agent runs no longer end when the model merely narrates next steps: answers
  that promise future work ("let me inspect...", "two reads will finish
  coverage") without a tool call are nudged up to twice per run to invoke
  tools, discover needed ones first, or answer outright, and each nudge shows
  in the activity pane. The prompt and loop guidance forbid narrating tool
  calls in prose, and data-only sessions state explicitly that byte and string
  inspection requires `discover_investigation_tools` before content tools
  become callable.
- `:report` exports the saved agent conversation and evidence as a
  deterministic Markdown report beside the workspace database: target identity,
  the latest shareable recap when present, the conversation without tool
  transcripts, and a bounded evidence inventory with typed locations.
- Agent answers now follow a self-contained report shape: a plain-language
  verdict, `Observed:`/`Inferred:` findings with evidence citations, explicit
  `Unknown:`/`Limitation:` bullets, and one prioritized next step, so reports
  stay readable and ready to share instead of continuing an earlier outline.
  Substantial reports end with a short shareable recap suitable for public
  posting; budget-limited partial answers keep the same shape and omit that
  recap because incomplete findings must not be published.
- `F6` and `Ctrl+Right` now always open the full agent workspace instead of
  silently changing focus in the split layout or toggling back to disassembly;
  `Ctrl+Left` always restores analysis and `Ctrl+Tab` remains the explicit
  workspace toggle.
- The focused agent desk now offers `a` to analyze the current selection, `t`
  for evidence-led whole-target triage, and `r` to retry the latest question
  after a provider failure without duplicating its ledger entry. Error cards
  surface retry and provider-setup actions directly in the conversation.
- Ordinary typing in the focused agent desk now starts an inline chat composer
  without losing the first character. The draft, selected model identity, and
  send/cancel guidance stay inside the conversation instead of the global
  command footer.
- Agent-desk actions now use `Alt+A/T/R/S/F/Z/E`, leaving every unmodified
  printable letter available to start a message. Questions beginning with
  action-like words such as "analyze", "trace", or "explain" no longer trigger
  a shortcut or lose their first character.
- The inline agent composer now supports Unicode-safe cursor editing,
  Home/End, Delete/Backspace, Ctrl+U, Shift+Enter multiline drafts, and bounded
  bracketed paste. Model/tool progress redraws every 100 ms while active, so a
  completed response no longer waits for an unrelated keypress to appear.
- The Agent activity pane now exposes the exact target filename, detected
  format/architecture, current function/address or raw-file offset, and a
  bounded live trace of recently completed analysis tools with evidence
  addresses.
- Plain Up/Down now scrolls the focused agent chat or evidence detail, with
  Ctrl+Up/Down for faster movement and Home/End for bounds. `j`/`k` or
  Shift+Up/Down selects findings, and scrolling is clamped before blank space.
- The chat renders a bounded 32-message conversation instead of only four
  entries. New answers follow the newest line; scrolling upward visibly enters
  `HISTORY` mode and End returns to the `LIVE` tail.
- The investigation desk is now a first-class focus and zoom target:
  `Ctrl+Left`/`Ctrl+Right`, `Ctrl+Tab`, or `F6` moves between it and analysis,
  a visible active border confirms focus, and `z` maximizes/restores the
  complete chat-and-evidence workspace without losing conversation state.
- Agent conversations now show the configured model's readable identity (such
  as `GLM5.3 Flash`) instead of a generic assistant name. Role badges, semantic
  evidence colors, worker-state indicators, and a wide fullscreen layout make
  long investigations easier to scan without relying on color alone.
- The TUI now opens with its investigation desk visible, and `i` starts an
  agent message from anywhere in the workspace. Provider readiness is shown in
  the chat pane.
- The embedded tool-using agent supports OpenRouter, OpenAI, and custom
  OpenAI-compatible chat-completions endpoints in addition to local Ollama.
  Hosted API credentials are kept out of child process command lines and saved
  investigation data.
- Provider setup now presents provider and model choices in the investigation
  sidebar. Provider, model, and base URL are remembered in the user's Knife
  config; API keys are stored separately in the operating-system credential
  vault and remain masked in the TUI. Saved tool transcripts are
  excluded from model protocol history, recent conversation and live tool
  previews are bounded, and a new answer always switches the pane back from
  evidence detail to conversation.
- The TUI and embedded agent can open any readable file. Unknown, malformed,
  or unsupported containers receive an explicit data-only workspace with raw
  bytes and non-code analysis tools instead of being rejected or pretending
  that code recovery ran.
- Reaching the agent's round or tool budget now triggers a tool-free synthesis
  turn rather than failing the investigation. If synthesis fails, Knife still
  saves a marked partial result and its evidence. The chat pane presents a
  compact human/Knife thread and keeps protocol transcripts in findings.

## v1.8.3

- **WAT listing for WebAssembly functions** (`knife wat`, MCP `wat` tool).
  Linear, depth-aware decode of one function body — control flow
  (block/loop/if/else/end with indentation), calls, memarg loads/stores,
  br_table, the numeric opcode set, and the 0xFC misc prefix — rendered at
  body file offsets so addresses line up with the section table and symbols.
  Function bodies export their export names as symbol names when the `name`
  section does not name them (wasm-bindgen builds keep their
  `workbenchengine_*` / `classify` names this way). Unsupported opcodes
  (SIMD 0xFD) stop the listing with an explicit marker instead of a guess.
- **WebAssembly support.** `knife info/sections/imports/exports/strings/hashes/
  map/entropy/scan/diff` now work on `.wasm` modules. The section table,
  imports grouped by module, exports, custom sections (with a decoded
  `producers` toolchain fingerprint and `name`-section detection), memory
  pages, and function-body locations all come from knife's own spec walker —
  goblin has no wasm parser. Every content parser degrades section-by-section:
  a truncated or hostile module keeps the rows that parsed, records a
  `trailing` region for what a broken table left behind, and notes what could
  not be walked. Code views (`dis`, `funcs`, `pseudo`, `graph`, `audit`) refuse
  with the architecture diagnostic, since there is no wasm lifter. The MCP
  server now serves read tools (`info`, `hashes`, `entropy`, `strings`, …)
  from a data-only session, so non-native architectures get their full
  container view instead of a blanket refusal.

## v1.8.2

- Help now scrolls and wraps to the terminal width. Arrow keys, Page Up/Down,
  and Home/End navigate it; Esc or `?` closes it.
- Function, disassembly, pseudocode, and xref panes format only the visible
  rows when drawing. Mouse selection uses the same window as the renderer,
  including near the end of large lists and in split view.
- Tab skips an empty reference pane. Explicit `:focus references` and xref
  commands still reveal it; split view rejects focus on its hidden reference
  pane.

## v1.8.1

- ELF structure inspection now covers the file header, every program header,
  and every section header through the shared analysis API. `knife headers`
  prints the same deterministic report as the TUI and MCP, including raw
  values, decoded meanings, file offsets, entry sizes, and mapped addresses.
- The TUI adds filterable `:headers`, `:segments`, and `:section-headers`
  catalogs. Enter opens the selected on-disk bytes, `O` opens the containing
  table record, and `D` follows a mapped address into disassembly; raw windows
  remain explicitly labelled `OFF` so file offsets cannot be mistaken for
  virtual addresses.
- Pane control is keyboard-first: Tab and Shift+Tab move focus, `+` and `-`
  resize the focused pane, and `z` maximizes or restores it. Empty reference
  panes collapse automatically, while explicit focus reveals them again.
- The README demo now exercises the real ELF structure and adaptive-pane
  workflow.

## v1.8.0

- Removed YARA. The `yara` subcommand, `info --rules`, and the yara-x
  dependency are gone. Rule matching was a second opinion bolted onto triage
  rather than something the tool could reason about; capability detection,
  the constant scanner, and the transparent verdict score carry the triage
  story on their own, and the build drops its one heavyweight dependency.
- The pseudocode reads the arithmetic UCRT and MSVC actually emit. On
  ucrtbase.dll the share of instructions left as verbatim assembly fell from
  2.86% to 0.62% (7,079 to 1,527 of 247,363), and the functions containing any
  fell from 1,088 to 520:
  - AVX is read like its legacy twins. ucrtbase is built with VEX encodings,
    and every `v`-prefixed instruction was a comment: the moves (including the
    three-operand `vmovsd xmm1, xmm2, xmm3`, which copies its last source),
    the scalar arithmetic and compares, the zeroing xors, and the scalar FMA
    family, which now reads as the `a * b + c` one rounding computes.
  - `sbb reg, reg` — MSVC's branchless comparison — reads as the borrow it
    is: `(a < b) ? -1 : 0` after a `cmp`, `value != 0 ? -1 : 0` after a
    `neg`, and plain zero after a `test`/`and`/`or`, whose cleared carry is
    defined. A borrow this lifter cannot trace stays assembly.
  - `bt`/`bts`/`btr` read the bit they test into the branch that follows:
    `bts eax, 7` is `eax = eax | (1 << 7)` and the `jc` after a `bt` asks
    whether `((value >> 7) & 1) == 1`.
  - The one-operand widening multiply states both halves; the three-operand
    `imul dst, src, imm` no longer multiplies into the old destination
    (it printed `eax = eax * ecx` for `imul eax, ecx, 5`, a different
    product); BMI2 `shlx`/`shrx`/`sarx` read as shifts; a rotate by an
    immediate expands to its exact two shifts; the AVX conversions read as
    the casts they are; and `int3` padding and `vzeroupper` are dropped.
- A `ret` prints the value propagation recovered — `return 0x0`, not
  `eax = 0x0; return rax` — and the redundant assignment goes with it.
- `knife` with no argument opens a file explorer instead of printing usage.
  Directories sort first, PE/ELF/Mach-O/archive files carry a badge sniffed
  from their magic bytes, `/` filters by name, and Enter hands the file to
  the analysis workspace. Quitting the workspace returns to the explorer in
  the same directory, so a folder of samples is one keypress per file.
  `knife tui` without a file and `knife <directory>` do the same.
- Split comparison in the TUI. `:split` clones the active listing into a
  second column and `:compare FUNC` pins a function (or a data view) there,
  so two functions sit side by side while the active pane keeps roaming.
  Tab walks between the columns; each keeps its own cursor, view mode,
  in-listing search and back/forward history. The references pane hides
  while split; `:only` (or `:close` on the listing) collapses back to one.
- `:reload` re-reads the target from disk and re-analyses it on a background
  worker, so a rebuilt or unpacked sample lands without restarting the
  session. Pane layout, filters and bookmarks survive; navigation into the
  old image does not. Annotations follow content identity: an unchanged file
  reloads into the same database, a changed file starts a fresh one, and a
  failed reload keeps the old session untouched.
- `:goto` accepts explicit address modes: `off:0xOFFSET` (alias `file:`)
  converts a file offset through the section table, and `va:0xADDRESS` pins
  a value to the static-VA space even when a symbol shares the text. Miss
  errors show the address as typed instead of adding the image base twice.
- A target with no recovered functions no longer refuses to open: the
  workspace starts on the first mapped bytes and the section, string and
  import catalogs stay available.
- Terminals below 24x6 show a resize notice instead of clipped fragments,
  and the README is half its former length.

## v1.7.0

- PE symbols come from the PDB when there is one. knife read no debug
  information at all, so a stripped MSVC binary showed `sub_140001234` where
  IDA, Ghidra and WinDbg show a name. The CodeView record in the image names the
  file to look for, and the GUID and age in it are both checked before a match
  is used: a PDB from a different build mislabels every function it touches,
  which is worse than having none. `--pdb PATH` overrides the search, and
  `knife info` says whether one was matched, missing or rejected, so a name out
  of a symbol file never looks like a name out of a heuristic. On knife's own
  binary that is 181,485 names across 279,213 functions, and none of them
  `sub_`.
- x64 switch statements are recovered. Jump-table resolution only understood the
  32-bit shape, `jmp [table + i*8]`, so across four real 64-bit binaries — 34,879
  recovered functions — knife resolved **no tables at all**. x64 does not branch
  through the table: it loads a 32-bit displacement out of it, adds the base
  back, and jumps through a register, and `jmp rax` was explicitly documented as
  having no table. Both shapes are now read. On ucrtbase.dll that is 0 tables to
  60, across 53 functions, and three functions that no control flow previously
  reached. Case bodies were absent from the CFG, the call graph, and `audit`'s
  reachability, so a dangerous call inside a switch was a sink knife believed
  nothing could reach.
- `pseudo`: an x64 switch reads as a switch, and a case label no longer states a
  value nobody checked. The jump through a register is lifted as a dispatch on
  the register the table was indexed by, not the one jumped through, which by
  then holds an address. The table load and the base-add are the dispatch
  itself and are dropped, so the selector still names what the reader last saw.
  Case labels were the position in the table printed as `case 0x0:`, which says
  the program compared the selector against zero; they now carry a real value
  only where the guarding range check confirms one — the compared expression
  must be the selector and the bound must match the number of entries — and
  read as `/* case 1 of 5 */` otherwise.
- `pseudo`: scalar floating point is decompiled. Moves, `+`/`-`/`*`/`/`, the
  `xorps xmm, xmm` that writes zero, the `comis`/`ucomis` compares that feed a
  branch, and the conversions as C casts. Two thirds of everything this lifter
  still could not read on a real C runtime was SSE, and a numeric function whose
  every step was a comment was not decompiled at all: across ucrtbase.dll,
  unmodelled instructions fall from 8.4% to 2.7%. Only the scalar forms are
  taken; a packed operation works on several lanes at once and `a * b` would
  describe one of them. `xmm6`-`xmm15` join the callee-saved registers, so the
  Win64 spills the vector moves now expose stay out of the output.
- `pseudo`: integer division reads as division. `div` and `idiv` were
  unmodelled, so every divide in a function became a verbatim comment and threw
  away the values in `rax` and `rdx` with it. They now lift to `/` and `%` —
  but only where the high half of the dividend is provably the extension of the
  low one (`xor edx, edx`, or the `cdq` a signed divide runs first), because
  that is the condition under which `eax / src` is the whole division rather
  than a confident sentence about half of it. A genuine double-width dividend
  stays unmodelled. `ucrtbase!_ltoa`'s digit loop now reads
  `edx = r9d % edi; r9d = r9d / edi;`.
- `pseudo`: `neg` and `not` read as `-x` and `~x` instead of becoming comments.
  Both are bracketed by C's binding, not by the tree's shape, so a negated sum
  prints `-(a + b)` — `-a + b` is a different value. `ucrtbase!_ltoa`'s
  negative-number branch now reads `r9d = -r9d;`.
- `pseudo`: `lea` used as arithmetic reads as arithmetic. Every `lea` produced
  an address-of, so the commonest use of the instruction — adding without
  touching the flags — printed as `&(rbx + 2)`: an operator the machine never
  applied, around something C has no address for. It now yields `&name` only
  where the address names storage, a frame slot or a global, and the plain
  expression everywhere else. `lea` is 5% of the instructions in ucrtbase.dll.
- `pseudo`: `cbw`, `cwde` and `cdqe` read as the moves they are, the same way
  `movsxd` already did. Unmodelled they were worse than merely unhelpful: each
  writes the accumulator, so the value it held was dropped exactly where it was
  wanted, since `cdqe` is what a compiler puts in front of the
  `mov ecx, [base+rax*4+D]` that indexes a switch table.
- `pseudo`: a small negative that has been sign-extended to 64 bits prints as
  itself. `if (r10 < -0x1)` says what it means; `0xffffffffffffffff` leaves the
  reader doing the arithmetic and invites them to read a sentinel as a mask.
  Only where it is unambiguous, so `0xffffffff` and `0xffffffff00000000` are
  untouched.
- `pseudo`: an indirect call whose target cannot be resolved reads as
  `(*rax)(...)` or `(*(rcx + 0x18))(...)`. It used to render as `sub()`, which
  looks like a call to a function named `sub` — the prefix Knife gives every
  function it recovers without a symbol.
- `pseudo` no longer hangs. Recovering a function's signature walked the call
  graph to a depth of eight, marking each function as visited and unmarking it
  on the way out, so a function reachable down several call paths was walked
  once per path. The backward walk for the return type did the same thing over
  basic blocks, cloning its visited set at every predecessor. Both are
  exponential, and on ucrtbase.dll two functions never finished at all —
  `sub_18000df50` now takes 3.7s and `sub_180005490` 1.0s. Answers are worked
  out once per function per remaining depth, which is what they depend on.
  Output is unchanged: five functions that did complete before decompile
  byte-for-byte identically, about 18% faster.
- The passes that lift instructions refuse an architecture they cannot read
  rather than guess at it. `pseudo`, `audit` and `drv` are x86/x64 only, but the
  gate in front of them admitted AArch64, so every four-byte ARM64 word went
  through the x86 decoder — dropped silently when it failed to decode, and
  lifted as some unrelated instruction when it happened to succeed. What came
  out was an empty body, or statements about registers the target does not have.
  They now name the architecture and point at `knife dis`, which does read it.
- Mach-O symbols reach the engine. They were parsed and then thrown away, so a
  Mach-O binary was analysed from its entry point alone and read as `sub_…`
  throughout even when every function in it was named — while PE and ELF both
  fed theirs in. A universal binary also says which of its slices is being
  analysed instead of silently choosing one.
- `dis` and `pseudo` answer `--json` with JSON. Both accepted the flag and
  returned ANSI-coloured prose with a zero exit, which a script cannot tell from
  success.
- `--json` now means JSON everywhere it is accepted, and is refused where it is
  not. `name`, `note`, `field`, `type`, `var`, `proto` and `typelib` confirm
  their edit as JSON instead of printing prose and exiting zero, which is how an
  applied edit and a quietly ignored one came to look identical to a script.
  `diff` emits the differences it already computed rather than communicating
  only through its exit status. `tui`, `mcp` and `completions` have no JSON form
  and now say so and exit non-zero — `knife --json tui FILE` used to open an
  interactive UI and hang whatever was waiting on it.
- The refusal a session gives on an unsupported architecture named the wrong
  set: it said x86/x64 on a gate that accepts AArch64 as well, so it described
  a narrower tool than the one refusing.
- `mcp`: a target the client no longer has to keep naming. `knife mcp --file
  PATH` binds a binary up front, the new `open` tool binds or replaces one
  mid-session, and `file` is optional on all thirty tools. An agent repeating an
  absolute path on every call spends its context on bookkeeping, and a path
  retyped is a path mistyped.
- `mcp`: the handshake now carries the protocol's `instructions` field, so a
  client is told what knife is, that it never runs the target, to call `open`
  first, and to reach for `audit` before disassembling a binary function by
  function. Thirty tools and no word on which one comes first is thirty tools an
  agent works out the hard way.
- `mcp`: a frame that is not valid JSON, or one over the size limit, is answered
  with a JSON-RPC parse error instead of being dropped. Dropping it kept the
  stream framed but left a client that had sent a request waiting for a reply
  that was never coming, and a hang says less about what went wrong than an
  error does.
- `docs/MCP.md`: what the MCP server is, how to register it with Claude Code,
  Claude Desktop and Cursor, the full table of thirty tools, a worked session,
  and why the transport is stdio. It had one row in the README's command table,
  which is not enough for anyone to install it.
- Signature scanning is about five times faster, and full triage more than
  three. The byte search compared the whole needle at every offset, and these
  needles are long — the AES S-box is 256 bytes — so it ran a length-checked
  compare 41 million times per signature on a 41 MB library. It now skips on the
  first byte and compares the rest only on a hit. `knife scan` on that file goes
  from 2.98s to 0.59s, and `knife FILE` from 4.01s to 1.14s: the scan was three
  quarters of what triage spent its time on.
- Function recovery is about 30% faster. Cross-references were recorded into a
  `BTreeMap<u64, Vec<_>>` as they were found, which costs a tree descent per
  reference and a heap allocation for every address seen for the first time.
  They are now collected flat and grouped once: on a 25 MB DLL with 1.1 million
  references, recovery drops from 3.39s to 2.39s.
- Bulk output is buffered. `println!` flushes on every newline, which is one
  write syscall per line; `strings`, `funcs`, and `dis` now share one buffer.
  `knife strings` on a 327 MB DLL (2.3 million literals) goes from 26.1s to
  3.9s, and a closed pipe (`knife strings big.dll | head`) exits cleanly
  instead of panicking.
- Instructions cost less memory. The raw bytes are held inline rather than in a
  `Vec` per instruction, and the resolved target name is boxed: 88 bytes plus an
  allocation each becomes 64 bytes and none. Peak memory analysing a 25 MB DLL
  falls from 1084 MB to 827 MB. Two whole-image copies are gone as well: one
  made even when a target had no staged patches, and one the interactive view
  made to hand the binary to its analysis thread.
- The analysis cache is schema 3: the instruction layout changed, and then the
  engine started resolving x64 jump tables, so a stored analysis of the same
  binary has different functions and edges in it. An older cache is recomputed
  rather than read. The schema is the only thing that invalidates a cache
  between builds of one version — the entry also records the knife version, but
  that does not change while a version is being developed.
- `tui`: the left pane grows with the terminal instead of staying at 38
  columns, and the attack-surface and function rows take their column widths
  from the pane they are drawn into, so the containing function is no longer
  cut short on every row.
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
