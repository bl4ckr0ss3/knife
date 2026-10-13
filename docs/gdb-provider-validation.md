# Runtime GDB integration validation

Runtime debugging is separate from static analysis and executes code. The
boundary requires authorization matching the exact workspace SHA-256; it does
not accept a generic allow-all switch. No GDB operation is advertised yet.

## Exporter observed results

GDB 17.1, with Python enabled, ran Knife's fixed capture script against the
benign `tests/fixtures/runtime_capture.c`, compiled with `cc -g -O0` into an
owned validation directory:
`/home/chixin/Desktop/Tools/knife-debug-check.XtifDn/runtime_capture`.
Fixture SHA-256:
`914bbf134824802f687d878ab3ad3dec9447f903c39d9db785f8e3a13fe97747`.

The launch disabled init files (`-nx -nh`), auto-loading before executable load
(`-iex 'set auto-load off'`), debuginfod, and shell startup. Inferior terminal
I/O was directed to `/dev/null`, keeping target output out of the exporter
record channel. These settings are not a sandbox.

- `starti` initially stopped inside the dynamic loader.
- Kernel auxiliary-vector `AT_ENTRY` identified the executable runtime entry
  `0x555555555040`; the script set a temporary breakpoint there and continued.
- After two instruction steps, runtime PC was `0x555555555046`, runtime SP was
  `0x7fffffffdb20`, with one `_start` frame and 64 captured memory bytes.
- The report explicitly said `target_execution: true`, steps completed 2 and
  no capture error. The script issued `kill` before returning its record.
- A subsequent `ps -p 293065` found no live inferior. This proves normal-path
  cleanup for this run, not deadline or fork-descendant cleanup.

The Rust boundary checks schema, unique records, hexadecimal runtime locations,
step/frame/memory bounds, and explicit failure reasons when no stop is present.
Runtime-to-static correlation uses the kernel entry relocation and checked
target executable-section membership; other-module PCs remain unknown.
All four Rust boundary regressions passed.

## Remaining gates

- Exact-byte executable snapshots and bounded Rust launch adapter.
- Verified inferior/descendant cleanup on process deadlines, including processes
  that create their own process groups.
- Explicit execution catalog/dispatch and approval policy shared by CLI, MCP
  and TUI; the embedded read-only agent must not silently gain execution tools.
- Runtime evidence envelopes, target identity, timestamp and typed locations.
- Live MCP tests on the owned fixture, then persistent debugger sessions,
  breakpoints, stepping, registers, memory and module-aware correlation.

This validates an exporter foundation, not a complete debugger integration.
No crackme or other user-supplied target was executed during this test.

Primary references:

- [GDB startup](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html)
- [GDB auto-loading](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading.html)
- [GDB starting an inferior](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Starting.html)
