<div align="center">

# knife

**Find the bug, not just the binary.** A reverse engineer's toolkit in Rust.

Parse, triage, disassemble, and audit **PE, ELF, and Mach-O** from one small
binary. Static only: it reads the bytes on disk and never runs the target.

[![ci](https://github.com/bl4ckr0ss3/knife/actions/workflows/ci.yml/badge.svg)](https://github.com/bl4ckr0ss3/knife/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/reknife.svg)](https://crates.io/crates/reknife)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![platforms](https://img.shields.io/badge/platform-linux%20%C2%B7%20macos%20%C2%B7%20windows-informational)

</div>

Most tools tell you a binary imports `memcpy`. `knife` reads the call sites and
tells you which one takes its length from a subtraction:

```text
$ knife sec 7z.dll
  [-] stack cookies (/GS)  disabled   no __security_cookie in the load config
      linear stack overflows reach the saved return address unchecked
  [-] CFG                  disabled   GUARD_CF clear
  WEAK   exposure score 7 · 3 of 6 mitigations missing or weakened

$ knife audit 7z.dll
  § AUDIT (145 FINDINGS)
  [-] copy-underflow   memcpy  sub_1000a6b4     @ 0x1000a72a
      copy length computed by subtraction (integer underflow to a huge size?)
  [-] copy-underflow   memset  sub_1000b028     @ 0x1000b0a2
      copy length computed by subtraction (integer underflow to a huge size?)
```

Those addresses are real functions in a stripped C++ parser that most
disassemblers never even recover: `knife` seeds function discovery from the PE
exception directory, taking `7z.dll` from 87 functions to 6472, and reads the
argument that reaches each dangerous call to rank the ones that look
exploitable. It works the same on a Linux daemon or a macOS dylib.

## Why

Pulling apart an unknown binary usually means five tools: one for the headers,
one for strings and IOCs, one for imports, one for entropy, one to disassemble.
`knife` is all of them in a single command, across three formats, with a
transparent triage verdict on top. Everything is static: it reads the bytes on
disk and never runs the file.

But the reason to reach for it is the next step, the one the other tools leave to
you: it says what the target is protected by, where its dangerous calls are,
which of them look actually wrong, and what can reach them. See
[for vulnerability research](#for-vulnerability-research).

## Install

```bash
# from crates.io (installs the `knife` command)
cargo install reknife

# prebuilt binary, no toolchain needed (cargo-binstall)
cargo binstall reknife

# latest from git
cargo install --git https://github.com/bl4ckr0ss3/knife
```

Or grab a prebuilt archive for Linux, macOS, or Windows from the
[Releases](https://github.com/bl4ckr0ss3/knife/releases) page and drop `knife`
on your `PATH`.

## Commands

One tool, many jobs, which is the point of a Swiss-army knife:

| command | what you get |
|---|---|
| `knife FILE` | full triage: verdict, hashes, sections, mitigations, capabilities, IOCs, artifacts, entry disasm |
| `knife sec FILE` | exploit mitigations, and what each missing one buys an attacker |
| `knife sinks FILE [--class C] [--all]` | dangerous-API call sites, grouped by bug class |
| `knife audit FILE [--reachable]` | sink call sites whose arguments look exploitable |
| `knife xrefs FILE TARGET` | what references a function, import, or address |
| `knife xrefs FILE --str TEXT` | what references the strings matching `TEXT` |
| `knife paths FILE TARGET [--from F]` | call chains that reach a sink from entry points and exports |
| `knife graph FILE [--from FUNC] [--reachable] [--dot]` | whole-program call graph, optionally rooted or Graphviz-ready |
| `knife graph FILE --func FUNC [--dot]` | one function's control-flow graph as text, JSON, or DOT |
| `knife tui FILE` | interactive: functions, listing, xrefs, naming and notes |
| `knife mcp` | Model Context Protocol server over stdio (tools for agents) |
| `knife name FILE ADDR NAME` | name an address; every later command uses it |
| `knife note FILE ADDR TEXT` | annotate an address; shows up in the disassembly |
| `knife field FILE --type TYPE OFFSET NAME [--data-type CTYPE]` | define a reusable, optionally typed structure field |
| `knife type FILE --func FUNC BASE TYPE` | bind a pseudocode base to a user type |
| `knife var FILE --func FUNC BASE NAME` | persistently rename a recovered pseudocode variable |
| `knife proto FILE --func FUNC --returns TYPE [--param TYPE ...]` | set an exact persistent function prototype |
| `knife patch FILE [--vaddr ADDR \| --off OFFSET] --bytes HEX` | stage binary edits without modifying the input file |
| `knife patch FILE [--vaddr ADDR \| --off OFFSET] --clear [--len N]` | restore a staged patch run or byte range |
| `knife patch FILE --export PATH [--force]` | atomically write a patched copy of the binary |
| `knife typelib FILE --export PATH` | export reusable layouts for other binaries |
| `knife typelib FILE --import PATH [--replace]` | merge or explicitly replace imported layouts |
| `knife db FILE` | everything you have stored for this binary |
| `knife funcs FILE [--by-refs]` | recover functions via control-flow analysis |
| `knife dis FILE --func NAME` | disassemble a whole function with labels and xrefs |
| `knife dis FILE [--vaddr X \| --off Y] [--count N]` | linear disassembly (x86/x64, AArch64) |
| `knife pseudo FILE --func NAME` | pseudocode view: lifted statements, calls with arguments |
| `knife sections FILE` | sections/segments with per-section entropy bars |
| `knife imports FILE` | imported libs and functions, suspicious APIs flagged |
| `knife exports FILE` | exported symbols |
| `knife caps FILE` | capabilities inferred from the symbol surface |
| `knife strings FILE --min N` | ASCII and UTF-16 strings |
| `knife iocs FILE` | URLs, IPs, domains, emails, wallets, reg keys, paths, defanged |
| `knife hashes FILE` | MD5 / SHA-1 / SHA-256 and imphash |
| `knife drv FILE [--reachable]` | kernel-driver / BYOVD analysis: identity, devices & symlinks, IRP dispatch, IOCTL surface, kernel primitives (optionally reachable-from-user-mode only), Authenticode signing, known-vulnerable-driver matches |
| `knife scan FILE` | crypto constants, packer markers, embedded formats |
| `knife yara RULES FILE` | match YARA rules (RULES is a file or a directory) |
| `knife map FILE` | whole-file entropy sparkline, packed regions flagged |
| `knife hex FILE --off O --len L` | hex dump |
| `knife ls FILE` | archive (.a/.lib) members |
| `knife completions SHELL` | shell completion script (bash, zsh, fish, powershell, elvish) |
| `knife diff A B` | compare two binaries' functions, imports, sections; exit 1 on any change |

Add `--json` to any analysis command for machine-readable output. `knife FILE`
is shorthand for `knife info FILE`, and `knife FILE --rules DIR` folds a YARA
pass into the verdict.

## For vulnerability research

Triage asks whether a binary is hostile. Research asks a different question,
where this binary can be broken, and four commands answer it.

**What is it protected by.** `knife sec` reads the mitigations out of the
container and says what each missing one costs you. It separates a claim from a
fact: a PE with `DYNAMIC_BASE` set but no `.reloc` section still loads at its
preferred base, a `GUARD_CF` flag with an empty guard function table checks
nothing, and an ELF with no `PT_GNU_STACK` header at all gets an executable
stack rather than a hardened one. Each line carries the consequence, so
`no __stack_chk_fail reference` is followed by what that means for a linear
overflow.

**Where the surface is.** `knife sinks` matches the binary against a catalogue
grouped by the mistake each API enables, unbounded copies, format strings,
input-sized stack allocation, command execution, temp-file races, weak
randomness, then resolves every one to concrete call sites. The output is
addresses in named functions, not an import list: on `kernel32.dll` that is 327
call sites across 17 APIs, and on a `vmlinux` image it finds 204 `strcpy` and
220 `sprintf` sites in named kernel functions. Statically linked targets work
too, because a defined symbol is matched the same way an import is.

**Which ones are actually wrong.** `knife sinks` still leaves you reading every
call. `knife audit` reads them first: for each catalogued call it recovers where
the interesting argument came from, and keeps only the sites whose provenance
matches a bug pattern. A `memcpy` whose length was just computed by a
subtraction (underflow to a huge size), an allocation sized by a multiply
(integer overflow), a `printf` whose format string is loaded from memory rather
than pointed at a constant, an unbounded `strcpy` reachable from an export.
Each finding names the function, the address, and what is wrong, ranked so the
exploitable-looking ones come first. Provenance is a bounded backward data-flow
walk over argument registers (x86/x64): it stops at calls, follows copies and
predecessor blocks, and joins origins across control-flow paths. When dangerous
arithmetic reaches a sink on only some paths, the finding says so instead of
dropping the candidate or claiming every path is dangerous. On a signed,
hardened `kernel32.dll` it surfaces a dozen sites, not a thousand. The same
provenance lattice marks function arguments and return values from external-input
APIs (`getenv`, `fgets`, `read`, `recv`, `GetCommandLine*`, and related calls),
so a tainted format string is distinguished from a generic runtime load.

**What reaches what.** `knife xrefs` answers "who calls this" for a function,
an imported API, or an address, and `--str` answers the other direction, which
code touches this string. `knife paths` walks the call graph backwards from a
sink to the entry point and the exports, printing the shortest chains, which is
the reachability question that decides whether a sink is worth your afternoon.

```bash
knife sec ./target                       # what am I up against
knife sinks ./target --class memory      # where could the bug be
knife audit ./target --reachable         # which sites look actually exploitable
knife xrefs ./target --str "/tmp/"       # who builds that path
knife paths ./target system              # can anything reach it
```

`knife graph` exports the same recovered edges used by paths and the TUI as a
deterministic artifact. With no selector it emits the whole-program call graph,
including imported and unresolved external callees. Repeat `--from FUNC` to
keep a forward-reachable subgraph, or use `--reachable` to root it at entry and
exports. `--func FUNC` switches to that function's basic-block CFG and marks
loop/cross edges back to earlier blocks. Add global `--json` for automation or
`--dot` for Graphviz:

```bash
knife graph driver.sys --reachable
knife graph driver.sys --from DriverEntry --from DispatchDeviceControl --json
knife graph driver.sys --func DispatchDeviceControl --dot > ioctl-cfg.dot
dot -Tsvg ioctl-cfg.dot -o ioctl-cfg.svg
```

Node and edge ordering is stable, duplicate calls collapse, symbol text is DOT
escaped, and an analysis-budget warning remains visible when recovery was
truncated.

For a worked example on a real, shipped binary, see
[finding CVE-2017-11882 with knife](docs/case-study-eqnedt32.md): `sec` shows the
Equation Editor has no mitigations, `audit` flags the font-name copy, and `dis`
confirms it is an `lstrcpy` of attacker data into a stack buffer.

**What you worked out.** Everything above is derived from the bytes and can be
recomputed at any time. What cannot be recomputed is what you understood, so
`knife name` and `knife note` write it down, and every later command reads it
back. Naming an address is not cosmetic: it tells the engine there is a function
there, which is how you make progress on a stripped binary.

```bash
knife name ./target 0x4017a0 parse_record      # sub_4017a0 is now parse_record
knife note ./target 0x4017c4 "len from packet" # shows up beside the instruction
knife funcs ./target | grep parse_record       # and in every other command
knife dis  ./target --func parse_record
```

**Somewhere to do it.** `knife tui` puts the same analysis behind a keyboard:
the function list on the left, the listing and cross-references on the right.
`↵` opens a function or follows the call under the cursor, `⌫` returns to where
you followed from, `/` filters the function list (or searches the code when the
listing is focused), `g` goes to an address or a symbol, `d` toggles decompiled
pseudocode, and `f` toggles a spatial function graph. Basic blocks are placed in
top-down CFG layers with routed cyan/amber flow, explicit loop-back markers, and
a fixed inspector showing the selected block's instructions and typed `TRUE`,
`FALSE`, `FLOW`, `RETURN`, or `TERMINAL` exits. Arrow keys move geometrically
between layers and sibling lanes; large switch layers use a selection-following
horizontal viewport instead of overlapping nodes. Click a node or press `↵` to
open the selected block in disassembly. In pseudocode, `t` binds the selected
field base to a reusable user type and `e` names that field; empty input clears
the binding or name. `p` edits the current function's exact prototype using
`RETURN (PARAM, PARAM)` syntax (for example `bool (CONTEXT *, size_t)`); the
existing value is prefilled and empty input clears it. In assembly, uppercase
`P` stages replacement bytes at the selected instruction; the current bytes are
prefilled, and submitting an empty value restores the complete patch run. `n` and
`c` name and annotate whatever the cursor is on. `s` cycles the left pane: function list, ranked
attack surface (the sink call sites the audit found worst first), and, for a
driver, the `knife drv` summary (devices, IRP dispatch, IOCTL surface,
primitives), then a whole-program analyst-type browser. The type browser groups
exact prototypes, reusable structure layouts, and scoped function/base bindings;
`/` filters names or facts, its detail rail shows the complete selected fact,
and `↵` opens the owning function for prototypes and bindings. The attack-surface view is severity-coded and opens an evidence
rail for the selected finding: pattern, sink, reachability, containing function,
the audit explanation, and a compact `SOURCE → DATA FLOW → SINK` signal chain;
`↵` jumps to the listed sink. The xrefs
pane is a list of its own: tab into it, and `↵` jumps to the reference's site. Operands that
point at a literal are annotated with the string itself, in the listing and in
the printed `dis --func`, and following one opens its bytes as a hex dump. The
mouse works too: the wheel scrolls the focused pane, a click focuses and
selects. Names, notes, staged patches, type layouts, bindings, and prototypes go to the same database the
command line writes, as you make them, so quitting is not a save step and `knife funcs` in another
terminal already agrees with you.

```bash
knife tui ./target
```

### Safe binary patch workspace

Knife treats edits as analysis facts, not destructive writes. The original
sample remains the database identity and is never changed in place. Staged
bytes are persisted with their expected originals, applied before function
recovery, disassembly, pseudocode, graphs, xrefs, and vulnerability analysis,
and kept in a separate derived-analysis cache. Overlapping edits preserve the
true original byte; restoring a byte removes it from the workspace. Bounds,
stale-input, malformed-hex, and overlapping on-disk records are rejected.

```bash
knife patch sample.exe --vaddr 0x401234 --bytes "31 c0 90" # stage by VA/RVA
knife patch sample.exe --off 0x834 --bytes "90 90"          # or file offset
knife patch sample.exe                                      # list patch runs
knife db sample.exe --json                                  # patches are project facts
knife dis sample.exe --func verify                          # analyzes staged bytes
knife patch sample.exe --vaddr 0x401234 --clear             # restore its run
knife patch sample.exe --export sample-patched.exe          # write a new file
```

Export uses a temporary file in the destination directory and then renames it,
refuses to overwrite the input, and requires `--force` for an existing output.
Changing any signed binary byte invalidates its existing digital signature;
Knife reports that explicitly during export. Clearing or changing patches
updates the TUI analysis immediately, while the command line applies them on
the next invocation.

The database is keyed by the file's SHA-256, so it follows the binary rather
than the path, and pointing knife at a different build never silently applies
the wrong names. Addresses are stored relative to the image base, in hex, as a
flat list, which means a database survives rebasing and can be diffed,
hand-edited, or sent to somebody else who has the same sample. It lives under
your platform's data directory by default; `--db PATH` puts it wherever you
want, and `knife db FILE` says which file is in use.

Code-analysis commands also keep a compact binary cache beside that database.
The cache holds only derived state (functions, CFGs, instructions and xrefs),
so it is safe to delete and never contains your names or notes. It is keyed by
the binary hash, Knife/cache version, analysis budget, and user-defined function
names; any mismatch transparently recomputes and replaces it. Set
`KNIFE_NO_CACHE=1` for a forced fresh analysis or `KNIFE_CACHE_DIR` to move the
cache to a different directory.

## Kernel drivers & BYOVD

`knife drv FILE` is the driver half of the audit. Everything goes through the
same engine, so a `.sys` parses, disassembles, and decompiles just like an
`.exe`; this pass turns the generic surface into the questions a driver
review actually asks:

| what | where |
|---|---|
| native-subsystem identity + `DriverEntry` | `driver` header line |
| `\Device\` / `\DosDevices\` names and their xrefs | devices list |
| `IRP_MJ_*` dispatch handlers (both historical x64 `MajorFunction` bases, 0x50 and 0x70, chosen by match count) | "irp dispatch" |
| IOCTL codes decoded as `CTL_CODE` (device type / function / method / access), `METHOD_NEITHER` flagged | "ioctl surface" |
| kernel primitives with call sites: physical-memory maps, arbitrary kernel R/W, driver loaders, registry/process, callbacks (the `ntoskrnl`/`hal`/`ndis` catalogue) | "kernel primitives" |
| Authenticode signer subjects + SHA-1 thumbprints (catalog-signed files without an embedded table are reported as unsigned) | "signing" |
| SHA-256 match against a bundled known-vulnerable-driver snapshot (loldrivers.io, 2000+ samples) | "known vulnerable driver" |

```bash
knife drv ./sus.sys                 # the whole picture
knife drv ./sus.sys --json          # machine-readable
knife drv ./sus.sys --reachable     # primitives user mode can actually drive
```

In the TUI (`knife tui`), the driver pane is navigable like the sinks: `s`/`v`
cycle to it, `↑/↓` move, `↵` jumps to a primitive call site, an IRP handler, or
a device string, and `n` names the selected row (so `DriverEntry` /
`DispatchDeviceControl` can be persisted to the database). `w` toggles
reachable-only, `3` gates on severity ≥ 3, and `/` filters the rows. The
disassembly shows type hints on driver-relevant instructions
(`; MajorFunction[14] /* IRP_MJ_DEVICE_CONTROL */`,
`; Parameters.DeviceIoControl.IoControlCode`).

The kernel API catalogue is a `sinks::CATALOG` extension (`ntapi.rs`), so
`knife sinks` and `knife audit` already see ntoskrnl calls, and ordinal
imports (`"ORDINAL N"`) are resolved against a table generated from the
host's own `ntoskrnl.exe` / `ndis.sys` export directories by
`scripts/gen-ntordinals.mjs` instead of being dropped. Windows-internals
structure layouts (`DRIVER_OBJECT`, `IRP`, `IO_STACK_LOCATION`,
`UNICODE_STRING`) live in `ktypes.rs`, awaiting the IR type-renaming pass;
the palatable parts (dispatch-slot IRP names, IOCTL `Parameters` offsets) are
already in use. `scripts/knife-ai.mjs` runs the `drv` pass and asks the model
for a driver-specific BYOVD section. The loldrivers snapshot is rebuilt with
`scripts/gen-loldrivers.mjs` from the project's public API.

## What makes it more than objdump

**Cross-format, one model.** [goblin](https://github.com/m4b/goblin) parses
PE/ELF/Mach-O into a single neutral model, so every command works on every
format. Validated on a signed Windows DLL, a stripped RISC-V ELF, and a macOS
x86-64 Mach-O.

**A real analysis engine.** `knife funcs` runs recursive-descent disassembly
seeded from the entry point and every named symbol, follows calls and branches,
splits basic blocks, resolves jump tables, builds a control-flow graph, and
counts cross-references. `knife dis --func` prints a whole function with `loc_`
labels, resolved call targets, and xrefs-to. On `kernel32.dll` it recovers 2605
functions, 1515 of them named. Everything is in virtual-address space, so the
address column, branch operands, and symbol names all agree.

**It finds code control flow cannot reach.** A stripped C++ binary reaches most
of its functions only through vtables and function pointers, which recursive
descent cannot follow, so descent alone sees a fraction of the code. On x64
Windows the PE exception directory lists every non-leaf function with its start
address, so knife seeds from it: on 7-Zip's `7z.dll` that is the difference
between recovering 87 functions and recovering 6472, and between `knife sinks`
finding one `memcpy` call site and finding 503. Chained unwind entries are
continuations, not functions, and are skipped, so the seeds are one per real
function.

**Imports resolve to names.** A call to a library function never goes there
directly: ELF routes it through a `.plt` stub that jumps via a GOT slot, and PE
linkers emit the same shape as `jmp [IAT]` thunks. knife follows both, so a call
site reads `call strcpy@plt` or `call KERNELBASE!CreateFileW` instead of an
anonymous `sub_`. That naming is what makes the sink and cross-reference
commands point at code rather than at an import table.

**A decompiler engine.** `knife pseudo --func NAME` runs a small IR over each
function: it lifts every instruction, propagates expressions (across block
boundaries too) so a run of `mov`/`lea`/`add` collapses into what it computes,
eliminates the dead intermediate assignments with a whole-function liveness
pass, and folds constants. It runs a stack-frame analysis, so `[ebp - 0x28]`
becomes the named local `var_28` and `[ebp + 8]` the argument `arg_8`, and the
frame bookkeeping (`mov ebp, esp`, the `sub esp` allocation, `push ebp`,
`leave`) is dropped. The CVE-2017-11882 overflow comes out as the single line
`lstrcpyA(&var_28, arg_8 + 0x1c);` with nothing around it. It then structures the
control flow: dominators and post-dominators drive a recursive emitter that
rebuilds nested `if`/`else` and `while`, and an indexed jump through a table
becomes a `switch` on its selector with each case structured. A function reads as
C rather than a goto chain. Conditions are recovered from whatever set the flags,
including the arithmetic ops (`dec`, `sub`, ...) that branch without a `cmp`, and
the compare is followed across blocks so a multi-way dispatch reads as a real
if/else-if chain. Register values are merged explicitly at CFG joins: identical
definitions remain one expression, differing definitions become SSA-style phi
values, and a provable two-arm diamond lowers to C's `condition ? a : b` instead
of losing the value at the join. Function signatures carry conservative recovered
types: ABI-visible parameters, returned values, string/address literals, and
known library prototypes constrain types such as `const char *`, `size_t`, and
`void *`; uncertain or conflicting evidence remains the explicit pointer-sized
`uintptr_t`. Direct calls to recovered 64-bit functions also recover positional
arguments interprocedurally: Knife follows the callee CFG and treats an ABI
register as an input only when an entry-reachable path reads it before an
unconditional write. Internal calls therefore retain their real argument
expressions instead of collapsing to `helper()`, while uncertain registers stay
omitted. Return types cross internal wrapper chains as well: when every return
path traces `rax`/`eax` back to the same typed API result, callers inherit that
type. The proof walks predecessor blocks and stops on cycles, conflicting paths,
or any intervening overwrite, so a stale `malloc` result never turns a later
integer return into a pointer. Parameter types propagate in the other direction:
Knife tracks original ABI arguments through direct register copies inside a
callee and observes which typed API or summarized internal parameter consumes
them. That evidence improves caller signatures and caller-side stack storage;
an internal `strlen` wrapper can recover both `const char * rcx` and a passed
`char var_8[]`. Writes and calls kill provenance, incompatible pointee evidence
degrades to `void *`, and unresolved values remain `uintptr_t`. Stack locals are declared from their use as scalars or addressed
storage: narrow and wide APIs recover `char[]` and `wchar_t[]`, opaque or
conflicting pointee evidence becomes `uint8_t[]`, and an unresolved array extent
is labelled instead of guessed. Actual constant-offset dereferences recover
stable synthetic aggregate fields (`ctx->field_18`) and constrain their ABI base
to a pointer; negative offsets use `field_m8`. Frame-relative slots and scaled
indexed accesses remain exact address expressions, because neither is sufficient
evidence for a structure member. The prototype catalog also supplies call arity
for recovered API arguments. The handful of edges that break nesting (a jump into a common
handler) become an explicit `goto` to a labelled block, so the flow is preserved
exactly, never approximated. It is not a full decompiler and does not pretend to
be: local/aggregate type recovery is still limited, and any instruction the
lifter does not model is printed verbatim so you always see where the clean lift
stops.

Recovered aggregate layouts can be refined without patching the binary or
losing the synthetic offset evidence:

```bash
knife field sample.exe --type CONTEXT 0x18 length --data-type size_t
knife field sample.exe --type CONTEXT 0x20 buffer --data-type "const uint8_t *"
knife type  sample.exe --func parse_packet rcx CONTEXT
knife var   sample.exe --func parse_packet rcx request
knife proto sample.exe --func parse_packet --returns bool \
  --param "CONTEXT *" --param "const uint8_t *" --param size_t
knife pseudo sample.exe --func parse_packet   # CONTEXT *request; request->length

# Reuse the same layout on another function/base, or undo either fact.
knife type  sample.exe --func validate_packet rdi CONTEXT
knife proto sample.exe --func parse_packet --clear
knife var   sample.exe --func parse_packet rcx --clear
knife field sample.exe --type CONTEXT 0x18 --clear
knife type  sample.exe --func parse_packet rcx --clear
```

Field data types are optional and use the same conservative C-type grammar as
prototypes. A typed member load participates in type inference: for example, a
`bool` member loaded into the return register can recover a `bool` function
return, and pointer members improve downstream call evidence. The TUI field
editor accepts either `name` or `name: C_TYPE`, preserving the old untyped
workflow.

Recovered registers, stack arguments, and locals can be given function-scoped
source-style aliases. Aliases affect signatures, declarations, expressions,
subregister uses, and member accesses, but never replace the stable recovered
identity used by type bindings and analysis. In pseudocode mode, put the cursor
on a line containing the variable and press `l`; an empty value restores the
recovered name. The CLI accepts either the recovered identity or its current
alias when changing or clearing it.

Type layouts are reusable inside the binary’s analysis database; bindings are
scoped by function and stable pseudocode base (`rcx`, `rdi`, `var_8`, ...), so
unrelated objects at the same offset never inherit each other’s field names.
Exact prototypes are scoped by function address and override recovered return
and ordered ABI parameter types; they also determine internal-call arity, so
opaque callees retain the arguments an analyst has established. Existing
databases remain valid, and `knife db` / `knife db --json` show layouts,
bindings, and prototypes.

Structure layouts can move between unrelated binaries without carrying unsafe
address-scoped facts:

```bash
knife typelib driver-a.sys --export windows-kernel-types.json
knife typelib driver-b.sys --import windows-kernel-types.json

# Merge rejects a different name at an occupied offset and changes nothing.
# Replace only the incoming named layouts when that is explicitly intended.
knife typelib driver-b.sys --import windows-kernel-types.json --replace
```

The portable JSON format is versioned (`schema: 1`), deterministic, and keeps
signed offsets readable. Optional field data types round-trip while old untyped
schema-1 libraries remain valid. It contains structure/field layouts only.
Function bindings, variable aliases, and prototypes remain in their binary
database because copying address facts between builds would silently mislabel
code.

Inside the TUI, cycle the left pane to **Types** with `s`, focus it with `Tab`,
then use uppercase `I` to merge a library, `R` to explicitly replace conflicting
incoming layouts, or `E` to export. The status line reports the exact imported
or exported type and field counts; successful imports refresh pseudocode in
place.

**Constant scanning.** `knife scan` fingerprints crypto and structure by their
byte signatures: AES S-boxes (generated from the GF(2⁸) definition, not stored
as literals), SHA-1/256/MD5/CRC32 constants in both byte orders, Base64
alphabets, packer markers, and embedded formats (zip, 7z, gzip, PNG, PDF, CLR
metadata). Embedded PEs are confirmed by walking the DOS to PE header chain.

**YARA built in.** `knife yara` runs rules through
[yara-x](https://github.com/VirusTotal/yara-x), VirusTotal's pure-Rust engine,
so there is no libyara C dependency. Matches can feed the triage verdict.

**Transparent triage.** The verdict (`CLEAN` / `LOW RISK` / `SUSPICIOUS` /
`MALICIOUS`) is an additive score where every point is a named signal you can
read. It weights concealment and anomaly (packing, RWX sections, high-entropy
overlays, tiny import tables) above raw capability, because a system DLL
legitimately exports powerful APIs. It shows what a binary can do and how it is
built, and leaves intent to you.

## Examples

```bash
# triage a sample and fold a rule directory into the verdict
knife sample.exe --rules ~/rules/

# busiest functions, then read the hot one
knife funcs sample.exe --by-refs
knife dis sample.exe --func sub_401240

# what crypto is this stripped blob doing?
knife scan blob.bin

# pull defanged network indicators as JSON
knife iocs sample.exe --json | jq '.[] | select(.kind=="url").value'
```

## Roadmap

- [x] Multi-format parsing (PE / ELF / Mach-O)
- [x] Static triage with a transparent verdict
- [x] Strings, IOCs, imphash, entropy map
- [x] Crypto/packer/embedded constant scanner
- [x] YARA (yara-x) matching
- [x] Analysis engine: functions, CFG, xrefs
- [x] IAT and PLT import-name resolution in disassembly
- [x] Exploit-mitigation audit (`knife sec`)
- [x] Sink call sites, code and data xrefs, call-graph reachability
- [x] Persistent analysis database: your names and notes, kept between sessions
- [x] Interactive TUI (spatial CFG / listing / xrefs, decompiled pseudocode, naming and notes)
- [x] Library-function identification (FLIRT-style)
- [x] AArch64 disassembly and PLT-veneer resolution
- [x] Argument-provenance bug audit (`knife audit`)
- [x] Function discovery from the PE exception directory (stripped C++ coverage)
- [x] Function discovery from ELF `.eh_frame_hdr` (the same win for ELF)
- [x] Versioned persistent cache for functions, CFGs, instructions and xrefs
- [x] Pseudocode view (`pseudo`): lifted statements, calls with arguments
- [x] Structured decompiler (`pseudo`): if/else and while reconstruction,
      cross-block expression propagation, dead-store elimination
- [x] Conservative typed signatures and stack locals from ABI/API evidence
- [x] Pointer and synthetic aggregate-field recovery from constant dereferences
- [x] Persistent reusable user types, field names, and scoped pointer bindings
- [x] Interprocedural argument recovery for direct internal 64-bit calls
- [x] Conservative return-type propagation through internal wrapper chains
- [x] Callee-to-caller parameter typing with CFG register provenance
- [x] Cached interprocedural summaries and persistent exact function prototypes
- [x] Versioned cross-binary structure libraries with transactional import
- [x] Typed structure fields with decompiler inference and TUI library management
- [x] Persistent function-scoped pseudocode variable aliases across CLI and TUI
- [x] Deterministic CFG and whole-program call-graph export (text/JSON/DOT)
- [x] Persistent non-destructive binary patch workspace with CLI/TUI editing and atomic export
- [x] Reusable `reknife` core library shared by CLI, TUI, and MCP clients

## Build from source

```bash
cargo build --release        # target/release/knife
cargo test
```

Needs Rust 1.88 or newer (2021 edition). No system libraries beyond the
platform default; the YARA engine and the terminal interface are both pure Rust.

## Contributing

Issues and pull requests are welcome. Please run `cargo fmt`, `cargo clippy`,
and `cargo test` before opening a PR; CI enforces all three across Linux,
macOS, and Windows. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
