# knife as an MCP server

`knife mcp` speaks the [Model Context Protocol](https://modelcontextprotocol.io)
over stdio, which turns every analysis in this repository into a tool an agent
can call: recover functions, disassemble one, read its pseudocode, rank the
dangerous call sites, trace where a sink's argument came from, and write names,
notes, prototypes and staged patches back to the database.

It is the same engine the command line and the TUI use. Nothing is reimplemented
for agents, so a finding an agent reports is one you can reproduce by hand with
`knife audit`.

**It never runs the target.** knife is a static tool: it reads the bytes on disk
and that is all. An agent driving it cannot execute the sample, which is the
property that makes it safe to point at malware.

## Install

```bash
cargo install reknife          # installs the `knife` command
```

Then register the server with your client.

**Claude Code**

```bash
claude mcp add knife -- knife mcp
```

**Claude Desktop** — `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "knife": {
      "command": "knife",
      "args": ["mcp"]
    }
  }
}
```

**Cursor** — `.cursor/mcp.json`, same shape:

```json
{
  "mcpServers": {
    "knife": { "command": "knife", "args": ["mcp"] }
  }
}
```

To pin the server to one binary for the whole session, add it to `args`:

```json
{ "command": "knife", "args": ["mcp", "--file", "/samples/suspect.dll"] }
```

## The target

A client works on one binary at a time, so the server remembers which one.

- `knife mcp --file PATH` binds a target at startup.
- The `open` tool binds or replaces it mid-session, and returns the same summary
  as `info` so you can see the file parsed.
- Any call that names a `file` explicitly rebinds the target to it.

After a target is bound, `file` is optional on every tool. With nothing bound
and no `file` argument, the call fails and says how to bind one.

The analysis is cached per target, so repeated calls against one binary run the
engine once.

## Tools

`open` first, then the read tools, then explicit project-write operations.

| tool | what it answers |
|---|---|
| `open` | analyse a binary and make it the session target |
| `provider_status` | optional external engines, versions, safety mode, licenses, limitations, and operations |
| `yarax_validate_rules` | compile bounded inline YARA rules and inspect their diagnostics/inventory without a target |
| `list_retained_results` | bounded results currently retained by this server process |
| `get_retained_result` | exact structured payload for a returned result reference |
| `session_status` | content identity, analysis coverage, per-target tool availability, limitations, and versioned evidence |
| `discover_investigation_tools` | tools grouped by investigation task, with operation policy and current availability |
| `explain_function` | evidence-linked function context, bounded instructions, callers, callees, and experimental pseudocode for an explanation |
| `trace_string_usage` | matching literals with recovered reference sites, containing functions, instruction text, and coverage limits |
| `inspect_input_validation` | candidate comparisons, branches, validation API calls, and dangerous-argument provenance; completeness is not established |
| `compare_engine_findings` | Knife/Rizin function boundaries and sizes, with agreement, disagreement and unknown fields |
| `investigation_status` | saved questions, hypotheses, recent conversation and evidence counts |
| `investigation_conflicts` | hypotheses with opposing evidence links, including supporting/contradicting record summaries and locations |
| `investigation_get_evidence` | exact saved evidence by ID |
| `investigation_ask` | persist a question in the project investigation |
| `investigation_append_message` | save external-agent answers or tool activity with validated evidence links for the TUI |
| `investigation_record_evidence` | save validated evidence belonging to the current target/workspace |
| `investigation_link_evidence` | persist supporting or contradicting links to a saved hypothesis |
| `info` | format, architecture, entry point, sections, function and import counts |
| `triage` | malware-triage verdict and the signals behind it |
| `hashes` | md5/sha1/sha256 and imphash |
| `entropy` | whole-file entropy and a bucketed map (packed or encrypted regions) |
| `hardening` | ASLR, DEP/NX, stack canary, CFG, RELRO and the rest |
| `signing` | Authenticode / code-signing summary (presence is not validity) |
| `signatures` | byte-signature hits: crypto constants, packers, embedded formats |
| `loldrivers` | whether the sha256 matches a known vulnerable driver |
| `list_functions` | recovered functions, with incoming call counts |
| `inspect_address_context` | section/file mapping, symbol, containing function, instruction, and xref counts for an address |
| `resolve_containing_function` | recovered function containing an interior static address |
| `address_to_file_offset` | checked static-VA to on-disk file-offset conversion |
| `read_function_instructions` | structured, cursor-paginated instruction rows, including bytes, targets, blocks, and file offsets |
| `disassemble` | one function's disassembly |
| `decompile` | one function's pseudocode |
| `xrefs` | what calls or jumps to an address or function |
| `callees` | what one function calls, resolved to names |
| `call_graph` | the call closure rooted at one function |
| `paths_to` | call chains reaching a function from entry points and exports |
| `sinks` | dangerous-API call sites by class, before ranking |
| `audit` | those call sites ranked by how exploitable the arguments look |
| `trace_taint` | for one function, each sink's argument provenance and the chains that reach it |
| `strings` | string literals matching a query, with reference counts |
| `iocs` | URLs, hosts, IPs, paths and registry keys pulled from strings |
| `imports` / `exports` | what the binary calls out to, and what it offers |
| `elf_structure` | ELF header, program-header, or section-header records with exact file ranges |
| `capabilities` | behaviour inferred from imports and exports, by category |
| `driver_report` | Windows-driver / BYOVD surface: devices, IRP dispatch, decoded IOCTLs |
| `read_bytes` | an exact-length bounded hex+ascii dump at a static virtual address |
| `rizin_*` | independent Rizin metadata, symbols, functions, disassembly, xrefs, CFG, and call-graph evidence |
| `yarax_scan` / `yarax_scan_range` | native YARA-X matching over the exact workspace or a mapped static-address range |
| `set_name` | persist an analyst name for the code at an address |
| `set_note` | attach an analyst note to an address |
| `set_prototype` | set a function's return and parameter C types |
| `stage_patch` | stage a byte patch at a file offset (staged only; `knife patch --export` writes it) |

The four `set_*`/`stage_*` tools mutate the saved database beside the binary,
exactly as the equivalent CLI commands do. Nothing writes to the binary itself.

Every advertised MCP tool comes from the shared Knife operation registry and
carries machine-readable annotations describing
whether it is read-only or writes the analysis project. Future debugger and
export operations use the same contract to distinguish target execution and
target writes. `session_status` and the address/instruction operations return a
versioned evidence envelope that separates observations, static-analysis
inferences, and unknowns and carries limitations with the result.
`session_status` also tells an agent which operations are usable for the active
format and architecture and gives an explicit reason when one is not. Existing
tools retain their response shapes while they migrate to that envelope.

Successful tool calls include a content-addressed `knife/resultId` in their MCP
result metadata. The corresponding structured payload is retained in a bounded,
process-local ledger and can be recovered with `get_retained_result` without an
active target. Identical operation results share a stable reference. The ledger
evicts its oldest entries when its item or byte budget is reached.

`list_functions`, `strings`, and `read_function_instructions` accept an optional
opaque `cursor`. Their results include `next_cursor` when another page exists.
Cursors are bound to the query that created them, so changing a filter, function,
or instruction start address while continuing a page is rejected.

## A session

```
open      { "file": "/samples/suspect.sys" }
session_status {}
triage    {}
audit     { "reachable": true }
trace_taint { "selector": "sub_140003a10" }
decompile { "selector": "sub_140003a10" }
set_name  { "address": "0x140003a10", "name": "handle_ioctl_88000004" }
```

Only the first call names the file. After that the agent spends its context on
the binary rather than on retyping a path.

## Why stdio and not HTTP

Some MCP servers for RE tooling run over HTTP because they live inside an
already-running process — an x64dbg or IDA plugin cannot be spawned by the
client, so it listens on a port and the client dials in, which then needs a
bearer token and an unencrypted local socket to defend.

knife has no such constraint. Its analysis is a function of a file on disk, so
the client spawns it directly and the pipe is the security boundary: no port, no
token, no listener, and nothing to reach it from another process on the machine.
Adding a network transport here would add an attack surface to buy back a
property stdio already has.

## Limits

- One target at a time per server process. Point two clients at two processes.
- The engines that lift instructions — `decompile`, `audit`, `trace_taint`,
  `driver_report` — are x86/x64 only, and refuse other architectures rather than
  guessing. `disassemble` also handles AArch64.
- Results are capped (400 rows) so a pathological binary cannot return an
  unbounded blob.
- Analysis is bounded by an instruction budget; a very large binary is truncated
  rather than allowed to run away.
