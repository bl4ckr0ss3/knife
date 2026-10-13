# Investigation desk

The investigation desk is being developed alongside the existing listing.
Open it with `:investigation`. `:ask <question>` persists an analyst question
and conversation entry. When `KNIFE_AGENT_MODEL` is configured, it also starts
a background conversation with a local Ollama model.

```sh
export KNIFE_AGENT_MODEL=qwen3
export KNIFE_OLLAMA_URL=http://127.0.0.1:11434
knife tui ./sample.exe
```

Install and serve the model with Ollama before opening Knife. The adapter uses
Ollama's documented `/api/chat` tool-call protocol and requires `curl` on PATH.
There is no default model or account requirement. This first transport accepts
localhost HTTP only. Each request has a 60-second timeout, the loop allows eight
model rounds and 24 tool calls, and serialized context is capped at 96 KiB.

The model can invoke registered analysis reads. Tool activity appears while it
works; the resulting answer, tool-response previews, and evidence records are
persisted. The prompt requires observed facts, inferences, unknowns, evidence
IDs, and static addresses. Model compliance with those instructions still needs
to be assessed by the analyst. Project mutation and target execution are not
available to this initial loop. Responses currently arrive after each complete
model request; token streaming is outstanding.

The model begins with a small investigation tool set. Calling
`discover_investigation_tools` adds schemas for the selected task on its next
round. Tasks include triage, code, strings, validation, memory and external
analysis; discovery reports availability and operation policy.

Protocol reference: <https://docs.ollama.com/capabilities/tool-calling>

Run an existing analysis operation with:

```text
:run-tool inspect_address_context {"selector":"main"}
:run-tool read_function_instructions {"selector":"main","limit":20}
:run-tool session_status {}
:run-tool explain_function {"selector":"main"}
:run-tool trace_string_usage {"query":"password","limit":5}
:run-tool inspect_input_validation {"selector":"main"}
```

The worker reopens the saved project and checks that its workspace bytes match
the TUI before collecting results. Navigation remains responsive. Evidence
records and bounded tool responses are saved beside the annotation database in
an `.investigation.json` file. Up/Down selects evidence; Enter navigates to its
first static location. Esc closes the desk; `:` returns to command input.
The desk separates conversation from findings. PgUp/PgDn browse older/newer
messages; Ctrl+Up/Down scroll the selected message, including saved tool output.

`:interrupt` discards the active worker result and stops the model loop before
its next request or tool call. An in-flight model request or analysis operation
may finish in the background under its existing deadline. Native engine work
does not yet have a cancellation guarantee.

The ledger stores explicit supporting and contradicting evidence links.
Opposing links leave a hypothesis unresolved. Linking evidence is not an
automatic assertion that a hypothesis is true.

`:contradictions` opens the desk with only hypotheses that have both supporting
and contradicting links. `investigation_conflicts` returns the linked record
summaries and locations for external clients. This view reports analyst-recorded
conflicts; automatic cross-engine contradiction detection is still outstanding.

External MCP clients can use `investigation_status` and
`investigation_get_evidence` to inspect the same saved ledger.
`investigation_ask`, `investigation_record_evidence`, and
`investigation_link_evidence` are project-write operations. Evidence imports
validate content-derived IDs and require the active original or staged target
hash. Saves use an exclusive lock and compare the disk revision with the loaded
revision. A stale writer is rejected instead of overwriting another client's
changes. Use `:investigation-reload` to refresh a TUI ledger after such a
conflict; this refuses while a worker is active. A crash may leave an
`.investigation.lock` file that needs inspection before removal.

## Implementation scope still outstanding

- Additional model transports (including GLM), token streaming and context management.
- Approval interaction for model-requested project mutations.
- Engine cancellation, activity history, and complete result navigation.
- CLI ledger operations and import/export.
- Deeper input-validation proofs, function explanations and string tracing.
- Cross-engine comparison and a dedicated contradiction view.
- capa, Ghidra and runtime debugger provider integrations.
- Tool discovery by investigation task and verified expansion toward 100–120 tools.

The initial desk and ledger are a foundation for these requirements, not a
claim that the conversational agent is complete.
