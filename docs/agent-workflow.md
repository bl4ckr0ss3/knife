# External-agent investigation workflow

Knife's MCP server is the primary interface for an existing coding agent.
An external agent supplies the model, investigation decisions and explanations;
Knife supplies local analysis, evidence, navigation and saved project facts.
The optional local-model TUI is a companion interface, not a prerequisite.

Start the current build with:

```sh
cargo build --bin knife
./target/debug/knife mcp
```

Register that executable in your client's MCP configuration with the `mcp`
argument, using its absolute path. See [MCP.md](MCP.md) for configuration examples.
Knife itself needs no model credentials in this mode.

Give the external agent this investigation procedure:

1. Call `open` with the target path, then `session_status`. Establish the target
   hash, format, architecture, staged workspace identity and analysis coverage.
   `open` initially parses container facts; null function counts mean code
   analysis has not run, not that the target has no functions.
2. Discover tools for the investigation task. Inspect hardening, imports,
   strings and audit results as appropriate. Treat capability names as
   hypotheses rather than established runtime behavior.
3. Follow concrete references: `trace_string_usage`, `explain_function`,
   `read_function_instructions`, callers, callees and provenance. Continue
   paginated results when the question requires more coverage.
4. Compare uncertain native findings with independent provider results.
   Explain agreement, disagreement and missing evidence.
5. Preserve questions and supporting/contradicting evidence through the
   investigation ledger operations. Project-write tools are deliberate edits;
   ask the analyst before an unrequested rename, annotation or patch.
6. Report observed bytes/instructions separately from inferred behavior and
   unknowns. Cite evidence IDs and addresses. Do not report an empty bounded
   search as proof that behavior is absent.
7. When reconstructing a feature, test the reconstruction against observed
   behavior or supplied test cases. State when runtime comparison is unavailable.

## Dogfooding

Use the real MCP transport on real targets and preserve concise notes about
misleading fields, missing navigation, truncation and provider failures. Fix
those problems in shared handlers, add a regression, and repeat the same
investigation. This is how Knife improves; it does not modify its own code or
model weights automatically.

Current coverage is native static analysis plus WebAssembly and the registered
providers. Broad REA-style application, managed-code, browser, firmware and
runtime-debugger coverage is still under development.
