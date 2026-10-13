# Ghidra MCP field validation

The actual `target/debug/knife mcp` stdio server was driven by
`scripts/validate-ghidra-mcp.py`, using the portable Ghidra 12.1.4 and JDK 21
recorded in `ghidra-provider-validation.md`. No target code was executed.

## ELF observed results

Target: `/usr/bin/true`, workspace SHA-256
`913a39cd38f353497086bcf317b12f91f93c23b51869cea763b8340b4f84cfd3`.

- Initialize and tool discovery exposed both Ghidra operations.
- Open and session status succeeded before provider requests.
- Inventory recovered 134 functions with `partial: false`; the first two-row
  page took 22.811 seconds.
- The second page took 0.007 seconds and retained the same report digest.
- `_DT_INIT` was at Ghidra static address `0x102000`, address space `ram`, file
  offset 8192, and Knife static address `0x2000`.
- Decompilation completed and was not partial. Its output conditionally calls
  the imported `__gmon_start__` pointer. This describes inferred pseudocode,
  not demonstrated behavior.
- The evidence location was static address 8192, file offset 8192 and symbol
  `_DT_INIT`, with no runtime address. Imported SHA-256 matched workspace SHA-256.

This validates the ELF inventory/pagination/decompilation path through MCP.
It does not prove all architectures, packed targets, or runtime debugging.
## PE observed results

Target: `/home/chixin/Desktop/Crackme/CrackGothGirlsMedium.exe`, workspace SHA-256
`7937ca87a6b7f9fb4ffa25f8bbe7193ae501bd4c381a11360812aa3b4ae5a99e`.

- Inventory recovered 869 functions, `partial: false`; the first page took
  57.418 seconds. The cached second page took 0.034 seconds with the same digest.
- `FUN_140001000` had Ghidra/Knife static address `0x140001000`, file offset
  1024, and reported size 2466 bytes. Its decompilation completed, untruncated
  and not partial. Ghidra emitted an overlapping-global-symbol warning in the
  pseudocode; this warning is retained, not suppressed.
- Evidence carried static address 5368713216 and file offset 1024, no runtime
  address; the imported sample hash matched workspace bytes.
- Private projects were removed after both ELF and PE runs.

Knife's earlier native recovery found 786 functions on this target. The count
difference is an observed cross-engine disagreement, not proof that either
engine is correct. Function-level correlation and boundary inspection are
needed before attributing a cause.

The initial runs covered inventory, paging and decompilation. The reusable
script now additionally checks exact retained-result retrieval and native
navigation at the mapped entry. The extended ELF rerun passed: first page
18.867 seconds, cached second page 0.007 seconds, same 134-function inventory.

## Boundary hardening

Source offsets alone do not prove address equivalence for overlay spaces that
reuse the same bytes. Knife now only correlates the ordinary Ghidra `ram`
address space to native static addresses; other spaces remain unknown while
retaining their file-offset evidence. A regression covers this distinction.

## Combined comparison workflow

The live MCP script now requests `compare_engine_findings` with
`include_ghidra: true`, reusing the same 120-second inventory cache key. Ghidra
filters entries by exact source file offset, and the comparison includes its
independent evidence record.

The first validation assertion incorrectly required address agreement even
when Knife had not recovered a corresponding entry. The corrected rerun passed
on ELF: inventory 16.234 seconds, cached page 0.006 seconds. At file offset 8192,
Ghidra reported mapped address 8192 and size 27; Knife's corresponding function
address and size were both null. Both fields correctly remained `unknown`.
This is a recovery-coverage difference, not a proved native-engine bug or
evidence that the function is absent. Its decompilation still completed.

Seven provider regressions and the updated agent comparison regression passed.

## Lifecycle recovery follow-up

`readelf -d /usr/bin/true` independently showed `DT_INIT = 0x2000` and
`DT_FINI = 0x53b4`. Knife previously derived ELF metadata seeds only from the
unwind search table. The parser now adds these direct lifecycle addresses for
x86, x86-64 and AArch64 when they lie in file-backed allocated executable
sections, rejecting null/out-of-image/data addresses and deduplicating seeds.
Derived-analysis cache schema advanced to 4 so older recovery is recomputed.

Four ELF tests passed, including actual recovery of unreachable lifecycle
functions in a synthetic ELF and invalid-address rejection. Three cache
regressions passed. The shared CLI resolved `0x2000` as `sub_2000`, size 27,
with static/file evidence at 8192. The post-fix actual MCP rerun passed:
inventory 18.201 seconds, cached page 0.007 seconds. Knife and Ghidra now both
reported mapped entry 8192 and size 27, yielding agreement on both fields.
This fixes the observed missing recovery seed; agreement still does not prove
runtime semantics. Array-based constructors/destructors remain a
separate relocation-aware work item; they are not claimed implemented here.

Primary semantic reference:
[ELF ABI dynamic linking](https://gabi.xinuos.com/v42/elf/08-dynamic.html).
