# Investigation desk

The investigation desk opens alongside the listing on wide terminals and uses
the analysis area on narrow terminals. Press `i` anywhere to compose a message;
`:investigation` (or `:agent`) focuses the dock. `:ask <question>` does the same
from command mode. Every submitted question is persisted and, when a provider
is configured, starts a background tool-using conversation.

## Model providers

Press `S` in the TUI (or run `:agent-setup`) to enter the provider, model,
optional base URL, and API key without leaving Knife. Provider and model choices
appear in the sidebar and can be selected with Up/Down; an exact provider model
ID can still be typed. Knife remembers the non-secret settings in
`$XDG_CONFIG_HOME/knife/agent.json` (or `~/.config/knife/agent.json`). The
masked API key is stored separately by the operating-system credential vault,
never in that JSON file, the project, investigation ledger, command history, or
an environment file. Environment variables remain available and take
precedence for scripted startup.

Ollama remains the no-account local default:

```sh
export KNIFE_AGENT_MODEL=qwen3
export KNIFE_OLLAMA_URL=http://127.0.0.1:11434
knife tui ./sample.exe
```

Install and serve the model with Ollama before opening Knife. The adapter uses
Ollama's documented `/api/chat` tool-call protocol and requires `curl` on PATH.
The Ollama transport accepts localhost HTTP only. OpenRouter uses its
OpenAI-compatible tool-call endpoint:

```sh
export KNIFE_AGENT_PROVIDER=openrouter
export KNIFE_AGENT_MODEL=anthropic/claude-sonnet-4
export OPENROUTER_API_KEY='...'
knife tui ./sample.exe
```

Knife also accepts `KNIFE_AGENT_PROVIDER=openai` with `OPENAI_API_KEY`, or
`KNIFE_AGENT_PROVIDER=compatible` with `KNIFE_AGENT_BASE_URL` and
`KNIFE_AGENT_API_KEY`. Compatible endpoints must use HTTPS, except localhost
HTTP. API keys are never saved in the investigation ledger or placed on the
`curl` command line. If the OS vault is unavailable, Knife clearly marks the
key as session-only while still remembering the non-secret preferences. The
request still sends the recent conversation and tool
results to the configured service, so use Ollama for targets that must remain
local. There is no default hosted model or account requirement.

Each request has a 60-second timeout, the loop allows eight model rounds and 24
tool calls, and serialized context is capped at 512 KiB. Before a new request,
Knife excludes saved tool transcripts from protocol history and retains a
bounded recent conversation window. Live tool results are also bounded, so a
large saved investigation cannot prevent a focused follow-up from starting.
If the model consumes the round or tool budget, Knife disables tools for one
final synthesis turn. A failed final synthesis still saves a clearly marked
partial answer, collected evidence, and tool activity instead of discarding the
investigation.

The model can invoke registered analysis reads. Tool activity appears while it
works; the resulting answer, tool-response previews, and evidence records are
persisted. The prompt requires observed facts, inferences, unknowns, evidence
IDs, and static addresses. Model compliance with those instructions still needs
to be assessed by the analyst. Project mutation and target execution are not
available to this initial loop. Responses currently arrive after each complete
model request; token streaming is outstanding.

The complete embedded investigator prompt is intentionally auditable at
[`src/agent_system_prompt.md`](../src/agent_system_prompt.md). Repository-level
instructions for coding agents live in [`AGENTS.md`](../AGENTS.md); that file is
not sent to model providers or loaded from an analyzed target's directory.

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
an `.investigation.json` file. Press `i` to compose an agent message in the
ordinary command input. `F6` and `Ctrl+Right` always open/focus the desk,
`Ctrl+Left` always returns to analysis, and only `Ctrl+Tab` toggles between
them. This makes repeated focus commands idempotent instead of unexpectedly
sending the user back to disassembly. Focus changes preserve the thread,
selection, and scroll position. The focused desk uses a bright rounded border and a `FOCUSED` label;
press `z` there to maximize chat and evidence together, then `z` again to
restore the side-by-side workspace. Press `a` for an evidence-led analysis of
the current selection, `t` for complete-target triage, or `i` to write a custom
question. After a provider or network failure, `r` retries the latest saved
question without adding a duplicate ledger entry. While follow mode is enabled, completed agent tools move the listing
to their first static evidence address. Manual focus on the listing pauses that
behavior; `f` toggles it explicitly. `j`/`k` or Shift+Up/Down selects evidence; Enter navigates
to its first static location without closing the desk. Esc closes the desk;
`:` opens command input while leaving it visible.
The desk separates conversation from findings. Its chat pane shows a compact
thread of recent analyst and Knife messages rather than exposing protocol tool
transcripts as chat. Up/Down scroll the visible thread, Ctrl+Up/Down scroll it
three rows at a time, Home/End jump to its beginning/end, and PgUp/PgDn browse
older/newer messages. Scrolling is clamped so the conversation cannot disappear
into an empty pane. The latest 32 non-tool messages form the bounded visible
window. New answers follow the bottom automatically; scrolling upward changes
the title to `HISTORY`, and reaching the bottom or pressing End restores `LIVE`.
Use `j`/`k` or Shift+Up/Down to select evidence.
Press `e` to inspect selected evidence in the upper panel: producer, typed hex
locations, observation/inference/unknown statements, confidence and limitations.
The same scrolling keys move through these details; `e` returns to conversation. Sending a new
message and receiving an answer automatically return the upper pane to the
conversation so an old evidence-detail selection cannot hide the response.
Conversation badges identify `YOU` and the configured model by its readable
name rather than a generic assistant label. Colors distinguish the two roles
and call out observations, inferences, unknowns, limitations, and worker state;
the text labels remain authoritative for monochrome or low-color terminals.

`:interrupt` or Ctrl+C discards the active worker result and stops the model loop before
its next request or tool call. An in-flight model request or analysis operation
may finish in the background under its existing deadline. Native engine work
does not yet have a cancellation guarantee.

The ledger stores explicit supporting and contradicting evidence links.
External agents can save plans with `investigation_add_plan_step` and
`investigation_update_plan_step`. Status values are pending, running, completed
and blocked. Completion requires existing evidence links; recorded completion
is still an agent/analyst assertion, not automatic verification of the step.
The desk previews up to two unfinished steps; `investigation_status` returns a
bounded plan inventory. Existing ledgers load with an empty plan.
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

- Native GLM transport, token streaming and richer context management. GLM and
  other services already work when they expose an OpenAI-compatible endpoint.
- Approval interaction for model-requested project mutations.
- In-flight engine cancellation, activity history, and complete result navigation.
- CLI ledger operations and import/export.
- Deeper input-validation proofs, function explanations and string tracing.
- Cross-engine comparison and a dedicated contradiction view.
- Persistent live-event ingestion from external MCP clients (embedded agent
  tool completion already drives follow navigation).
- A complete runtime-debugger launch/session surface beyond the validated GDB
  capture foundation.

The initial desk and ledger are a foundation for these requirements, not a
claim that the conversational agent is complete.
