// Typed wrappers over the Tauri command surface. Every field mirrors a serde
// DTO in src-tauri/src/dto.rs; addresses are hex strings, never numbers.
import { invoke } from "@tauri-apps/api/core";

export interface FnRow {
  addr: string;
  name: string;
  named: boolean;
  size: number;
  blocks: number;
  incoming: number;
}

export interface OpenResult {
  path: string;
  title: string;
  format: string;
  arch: string;
  bits: number;
  functions: number;
  named: number;
  high_risk: number;
  is_driver: boolean;
}

export interface Annot {
  kind: "note" | "symbol" | "local" | "text" | "hint";
  text: string;
}

export type Line =
  | { kind: "label"; addr: string; text: string }
  | {
      kind: "insn";
      addr: string;
      mnemonic: string;
      operands: string;
      annot: Annot | null;
      target: string | null;
    }
  | { kind: "data"; addr: string; text: string };

export interface IrLine {
  label: boolean;
  text: string;
}

export interface XrefRow {
  addr: string;
  kind: string;
  site: string;
}

export interface Finding {
  addr: string;
  func: string | null;
  api: string;
  pattern: string;
  severity: number;
  detail: string;
  reachable: boolean;
  source: string;
}

export interface Section {
  name: string;
  vaddr: string;
  vsize: number;
  flags: string;
  entropy: number;
}

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
  imphash: string | null;
}

export interface Mitigation {
  name: string;
  state: string;
  kind: "info" | "warn" | "bad" | "na";
  detail: string;
  impact: string;
}

export interface Mitigations {
  exposure: string;
  score: number;
  missing: number;
  applicable: number;
  findings: Mitigation[];
}

export interface Signal {
  text: string;
  weight: number;
  kind: string;
}

export interface Triage {
  score: number;
  verdict: string;
  signals: Signal[];
}

export interface Signing {
  signed: boolean;
  entries: number;
  subjects: string[];
  thumbprints: string[];
  region_off: string | null;
  region_size: number | null;
  header_claims_signed: boolean;
}

export interface BinaryDetail {
  path: string;
  format: string;
  arch: string;
  bits: number;
  size: number;
  image_base: string;
  entry: string;
  subsystem: string | null;
  is_lib: boolean;
  is_stripped: boolean;
  functions: number;
  named: number;
  sections: Section[];
  hashes: Hashes;
  mitigations: Mitigations;
  triage: Triage;
  signing: Signing;
  capabilities: Capability[];
}

export interface CfgNode {
  id: string;
  addr: string;
  kind: "entry" | "block";
  insns: string[];
  count: number;
  bytes: number;
}

export interface CfgEdge {
  from: string;
  to: string;
  kind: "true" | "false" | "flow";
  back: boolean;
}

export interface Cfg {
  function: string;
  entry: string;
  nodes: CfgNode[];
  edges: CfgEdge[];
}

export interface StringRow {
  addr: string;
  text: string;
  wide: boolean;
  len: number;
  refs: number;
}

export interface ConsoleLine {
  kind: "cmd" | "out" | "err" | "hint";
  text: string;
}

export interface SymbolRow {
  module: string;
  name: string;
  addr: string | null;
  refs: number;
}

export interface TargetRow {
  path: string;
  title: string;
  active: boolean;
}

export interface FieldRef {
  base: string;
  offset: number;
  type_name: string | null;
  member: string;
}

export interface LineActions {
  field: FieldRef | null;
  variable: string | null;
}

export interface FactRow {
  kind: "prototype" | "structure" | "binding" | "variable";
  name: string;
  detail: string;
  addr: string | null;
}

export interface PatchRun {
  offset: string;
  vaddr: string | null;
  original: string;
  bytes: string;
  len: number;
}

export interface Capability {
  category: string;
  apis: string[];
}

export interface DriverReport {
  is_driver: boolean;
  why: string[];
  module: string;
  entry: string;
  entry_name: string;
  subsystem: string | null;
  kernel_imports: Array<[string, number]>;
  app_imports: string[];
  devices: Array<{ name: string; addr: string; wide: boolean; xrefs: number; created: boolean }>;
  irp: Array<{ major: number; name: string; derived: string; addr: string }>;
  ioctls: Array<{
    code: string;
    device_type: string;
    function: string;
    method: string;
    access: number;
    addr: string;
  }>;
  primitives: Array<{
    api: string;
    class: string;
    severity: number;
    reachable: boolean;
    sites: Array<{ from: string; in_func: string | null; at_off: string }>;
  }>;
  known_bad: Array<{
    file: string;
    vendor: string;
    product: string;
    category: string;
    signer: string;
    malicious: boolean;
  }>;
}

export interface PathHop {
  addr: string;
  name: string;
}

export interface PathRow {
  hops: PathHop[];
}

export interface YaraHit {
  rule: string;
  namespace: string;
  tags: string[];
  meta: Array<[string, string]>;
  patterns: Array<[string, number]>;
}

export interface AgentStep {
  tool: string;
  args: string;
  preview: string;
}

export interface ChatMessage {
  role: string;
  content?: string | null;
  tool_calls?: unknown;
  tool_call_id?: string | null;
  name?: string | null;
}

export interface Suggestion {
  kind: "rename" | "prototype";
  selector: string;
  new_name?: string;
  returns?: string;
  params?: string[];
  reason: string;
}

export interface AgentTurn {
  reply: string;
  steps: AgentStep[];
  history: ChatMessage[];
  suggestions: Suggestion[];
}

export const api = {
  openTarget: (path: string) => invoke<OpenResult>("open_target", { path }),
  listFunctions: (filter?: string, namedOnly?: boolean, limit?: number) =>
    invoke<FnRow[]>("list_functions", { filter, namedOnly, limit }),
  disassemble: (selector: string) => invoke<Line[]>("disassemble", { selector }),
  decompile: (selector: string) => invoke<IrLine[]>("decompile", { selector }),
  xrefs: (addr: string, direction: "to" | "from") =>
    invoke<XrefRow[]>("xrefs", { addr, direction }),
  pathsTo: (selector: string, max?: number) => invoke<PathRow[]>("paths_to", { selector, max }),
  attackSurface: () => invoke<Finding[]>("attack_surface"),
  binaryDetail: () => invoke<BinaryDetail>("binary_detail"),
  cfg: (selector: string) => invoke<Cfg>("cfg", { selector }),
  strings: (filter?: string, referencedOnly?: boolean, limit?: number) =>
    invoke<StringRow[]>("strings_list", { filter, referencedOnly, limit }),
  listTargets: () => invoke<TargetRow[]>("list_targets"),
  selectTarget: (path: string) => invoke<void>("select_target", { path }),
  closeTarget: (path: string) => invoke<void>("close_target", { path }),
  imports: (filter?: string) => invoke<SymbolRow[]>("imports", { filter }),
  exports: (filter?: string) => invoke<SymbolRow[]>("exports", { filter }),
  consoleExec: (line: string) => invoke<ConsoleLine[]>("console_exec", { line }),
  setName: (addr: string, name: string) => invoke<void>("set_name", { addr, name }),
  setNote: (addr: string, note: string) => invoke<void>("set_note", { addr, note }),

  // ── analyst workspace: everything that writes to the shared database ──
  clearName: (addr: string) => invoke<void>("clear_name", { addr }),
  clearNote: (addr: string) => invoke<void>("clear_note", { addr }),
  lineActions: (func: string) => invoke<LineActions[]>("line_actions", { func }),
  setPrototype: (func: string, returns: string, params: string[]) =>
    invoke<void>("set_prototype", { func, returns, params }),
  clearPrototype: (func: string) => invoke<void>("clear_prototype", { func }),
  bindType: (func: string, base: string, typeName: string) =>
    invoke<void>("bind_type", { func, base, typeName }),
  clearBinding: (func: string, base: string) => invoke<void>("clear_binding", { func, base }),
  setField: (typeName: string, offset: number, name: string, dataType?: string) =>
    invoke<void>("set_field", { typeName, offset, name, dataType }),
  clearField: (typeName: string, offset: number) =>
    invoke<void>("clear_field", { typeName, offset }),
  setVariable: (func: string, base: string, name: string) =>
    invoke<void>("set_variable", { func, base, name }),
  clearVariable: (func: string, base: string) => invoke<void>("clear_variable", { func, base }),
  stagePatch: (addr: string, bytes: string) => invoke<number>("stage_patch", { addr, bytes }),
  clearPatch: (offset: string) => invoke<void>("clear_patch", { offset }),
  patchRuns: () => invoke<PatchRun[]>("patch_runs"),
  exportPatched: (path: string) => invoke<string>("export_patched", { path }),
  agentSetKey: (key: string) => invoke<void>("agent_set_key", { key }),
  agentHasKey: () => invoke<boolean>("agent_has_key"),
  agentAsk: (model: string, question: string, history: ChatMessage[]) =>
    invoke<AgentTurn>("agent_ask", { model, question, history }),
  agentCancel: () => invoke<void>("agent_cancel"),
  setYaraRules: (path?: string) => invoke<number>("set_yara_rules", { path }),
  yaraMatches: () => invoke<[string | null, YaraHit[]]>("yara_matches"),
  driverReport: (minSeverity?: number, reachableOnly?: boolean) =>
    invoke<DriverReport | null>("driver_report", { minSeverity, reachableOnly }),
  analystFacts: (filter?: string) => invoke<FactRow[]>("analyst_facts", { filter }),
  importTypelib: (path: string, replace: boolean) =>
    invoke<string>("import_typelib", { path, replace }),
  exportTypelib: (path: string) => invoke<string>("export_typelib", { path }),
};
