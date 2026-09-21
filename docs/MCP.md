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

`open` first, then the read tools, then the four that write.

| tool | what it answers |
|---|---|
| `open` | analyse a binary and make it the session target |
| `info` | format, architecture, entry point, sections, function and import counts |
| `triage` | malware-triage verdict and the signals behind it |
| `hashes` | md5/sha1/sha256 and imphash |
| `entropy` | whole-file entropy and a bucketed map (packed or encrypted regions) |
| `hardening` | ASLR, DEP/NX, stack canary, CFG, RELRO and the rest |
| `signing` | Authenticode / code-signing summary (presence is not validity) |
| `signatures` | byte-signature hits: crypto constants, packers, embedded formats |
| `loldrivers` | whether the sha256 matches a known vulnerable driver |
| `list_functions` | recovered functions, with incoming call counts |
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
| `read_bytes` | a hex+ascii dump at a virtual address |
| `set_name` | persist an analyst name for the code at an address |
| `set_note` | attach an analyst note to an address |
| `set_prototype` | set a function's return and parameter C types |
| `stage_patch` | stage a byte patch at a file offset (staged only; `knife patch --export` writes it) |

The four `set_*`/`stage_*` tools mutate the saved database beside the binary,
exactly as the equivalent CLI commands do. Nothing writes to the binary itself.

## A session

```
open      { "file": "/samples/suspect.sys" }
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
