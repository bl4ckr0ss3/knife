# Agent-driven analysis platform

Knife is growing from a static terminal toolkit into an evidence-driven reverse
engineering platform. The CLI, TUI, MCP server, and future conversational agent
must remain clients of the same typed analysis operations. A feature is not
implemented separately in each front end.

## Invariants

1. An agent-visible conclusion distinguishes direct observation, inference, and
   unknowns, and links them to stable evidence records.
2. Every operation declares whether it reads analysis state, writes the project,
   executes a target, or writes a target. Front ends use that declaration for
   policy and approval decisions.
3. Static analysis never silently becomes target execution. Debug backends run
   out of process and are unavailable unless explicitly configured.
4. Results are bounded. Large results will use continuation tokens or retained
   evidence instead of silently dropping unreported coverage.
5. Target identity is content based and preserves both the original input digest
   and the staged workspace digest. Static and runtime addresses remain distinct
   types and are correlated only through an explicit mapping.
6. Engine limitations travel with results. A bounded search is never reported as
   proof that a behavior is absent.

## Baseline contract

The first platform slice consists of:

- `api::operations`: shared operation descriptors, safety classification,
  target requirements, and result delivery mode.
- `api::evidence`: versioned, content-addressed evidence records and structured
  observation/inference/unknown statements.
- `session_status`: establishes target identity, current analysis coverage, and
  important limitations at the start of an agent investigation, plus explicit
  per-target operation availability and unavailability reasons.
- MCP annotations: expose read-only, project-write, target-execution, and
  target-write policy as machine-readable metadata.
- One shared catalog and dispatch boundary for both analysis reads and approved
  project mutations. MCP contributes transport only; it no longer implements
  annotation or patch mutations itself.
- Query-scoped cursor pagination for catalog operations, starting with functions
  and strings, so continuation cannot accidentally be reused with another query.
- Agent-native address navigation: checked static-VA/file-offset correlation,
  containing-function and instruction context, and structured cursor-paginated
  function instructions. These operations preserve address-space distinctions
  and return evidence with explicit static-analysis limitations.
- Optional external providers are discoverable rather than assumed. The first
  Rizin adapter contributes independent, bounded static-analysis operations via
  fixed JSON commands; arbitrary provider commands are never agent-accessible.
- A bounded, content-addressed, process-local result ledger. MCP responses carry
  a result reference and target-free operations can list or retrieve the exact
  structured payload without recomputing analysis.
- Transport-neutral execution budgets, cancellation tokens, and a bounded job
  lifecycle with progress, result references, failures, and cooperative
  cancellation. Engines can adopt these primitives without depending on MCP.

Existing tools keep their response shapes during migration. New evidence-aware
operations return `OperationResult<T>`. Existing operations move to that envelope
individually with compatibility tests rather than through a flag-day rewrite.

## Delivery sequence

### 1. Complete the shared operation registry

- Give CLI, TUI, and MCP the same descriptors and handlers.
- Add stable operation versioning and target/architecture availability reasons.
- Migrate the remaining bounded catalogs to the shared pagination contract.
- Connect long-running engine passes to the shared execution/job primitives and
  expose the lifecycle through applicable front ends.

### 2. Add an investigation ledger

- Persist evidence and relationships by target hash.
- Record the operation, inputs, engine version, coverage, and limitations.
- Link findings to functions, instructions, strings, artifacts, and analyst facts.
- Export and import a deterministic evidence bundle.

### 3. Add the conversational TUI

- Conversation, investigation plan, tool activity, findings, and unknowns.
- One-key navigation from an evidence location to listing or pseudocode.
- Model-provider abstraction plus an external-agent/MCP mode.
- Explicit approval gates derived from operation access classification.

### 4. Introduce runtime debugging behind providers

- Begin with Linux x86-64 process launch/attach, threads, modules, registers,
  memory, breakpoints, stepping, signals, and static/runtime rebasing.
- Add Windows and LLDB backends without leaking backend-specific addresses into
  the shared API.
- Capture runtime events as evidence; do not overwrite static conclusions.

### 5. Deepen decompilation and add artifact providers

- SSA, calling conventions, variable recovery, alias analysis, interprocedural
  types, indirect calls, and structured control flow.
- Provider adapters for mature native engines while Knife's own engine grows.
- Managed code, Android, JavaScript/Electron, firmware, archives, crash dumps,
  and network captures as separately testable providers.

## Acceptance gates for every new capability

- One typed operation and one handler shared by all applicable front ends.
- Deterministic fixture coverage, malformed-input coverage, and bounded output.
- Evidence and explicit limitations for agent-facing conclusions.
- Correct access classification and no undeclared execution or file mutation.
- CLI/MCP/TUI parity, or a documented reason the front end is not applicable.
