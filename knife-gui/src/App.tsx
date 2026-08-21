import { useCallback, useEffect, useMemo, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import {
  api,
  type BinaryDetail,
  type Finding,
  type FnRow,
  type IrLine,
  type Line,
  type OpenResult,
  type StringRow,
  type XrefRow,
  type Cfg,
  type SymbolRow,
  type TargetRow,
  type LineActions,
  type FactRow,
  type PatchRun,
} from "./api";
import { FunctionList } from "./components/FunctionList";
import { CodeView } from "./components/CodeView";
import { XrefPane } from "./components/XrefPane";
import { DetailPanel } from "./components/DetailPanel";
import { AttackSurface } from "./components/AttackSurface";
import { GraphView } from "./components/GraphView";
import { StringsList } from "./components/StringsList";
import { Palette } from "./components/Palette";
import { LineMenu, pseudoMenu, type MenuItem } from "./components/LineMenu";
import { FactsList } from "./components/FactsList";
import { PatchList } from "./components/PatchList";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import { Console } from "./components/Console";
import { SymbolList } from "./components/SymbolList";

type Tab = "disasm" | "pseudo" | "graph";
type LeftView = "functions" | "attack" | "strings" | "imports" | "exports" | "facts" | "patches";

const FN_LIMIT = 20000;

/** Read a persisted number, tolerating a cleared or unreadable store. */
function loadNum(key: string, fallback: number): number {
  try {
    const raw = window.localStorage.getItem(key);
    const n = raw === null ? NaN : Number(raw);
    return Number.isFinite(n) ? n : fallback;
  } catch {
    return fallback;
  }
}

function saveNum(key: string, value: number) {
  try {
    window.localStorage.setItem(key, String(value));
  } catch {
    // A private window or blocked site data is not worth failing over.
  }
}

/** A draggable split between two panes. */
function Divider({ onDrag }: { onDrag: (dx: number) => void }) {
  return (
    <div
      className="divider"
      onMouseDown={(e) => {
        e.preventDefault();
        let last = e.clientX;
        const move = (m: MouseEvent) => {
          onDrag(m.clientX - last);
          last = m.clientX;
        };
        const up = () => {
          window.removeEventListener("mousemove", move);
          window.removeEventListener("mouseup", up);
        };
        window.addEventListener("mousemove", move);
        window.addEventListener("mouseup", up);
      }}
    />
  );
}

export default function App() {
  const [opened, setOpened] = useState<OpenResult | null>(null);
  const [targets, setTargets] = useState<TargetRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState("");
  // Pane sizes are dragged, not fixed: a wide monitor should give the code more
  // room, and a demangled C++ name needs a wider list than `sub_1400a2c0` does.
  const [leftW, setLeftW] = useState(() => loadNum("knife.leftW", 340));
  const [rightW, setRightW] = useState(() => loadNum("knife.rightW", 350));
  const [toasts, setToasts] = useState<Array<{ id: number; text: string }>>([]);
  const setError = useCallback((text: string | null) => {
    if (!text) return;
    // A backend error is a sentence, not a stack trace; strip the wrapper Tauri
    // adds so the toast reads as the engine wrote it.
    const clean = text.replace(/^Error:\s*/i, "");
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text: clean }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6000);
  }, []);

  const [functions, setFunctions] = useState<FnRow[]>([]);
  const [filter, setFilter] = useState("");
  const [leftView, setLeftView] = useState<LeftView>("functions");

  const [current, setCurrent] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("disasm");
  const [lines, setLines] = useState<Line[]>([]);
  const [ir, setIr] = useState<IrLine[]>([]);
  const [xrefs, setXrefs] = useState<XrefRow[]>([]);
  const [xrefDir, setXrefDir] = useState<"to" | "from">("to");
  const [history, setHistory] = useState<string[]>([]);

  const [cfg, setCfg] = useState<Cfg | null>(null);
  const [strings, setStrings] = useState<StringRow[]>([]);
  const [symbols, setSymbols] = useState<SymbolRow[]>([]);
  const [facts, setFacts] = useState<FactRow[]>([]);
  const [patches, setPatches] = useState<PatchRun[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [detail, setDetail] = useState<BinaryDetail | null>(null);

  const [palette, setPalette] = useState(false);
  const [acts, setActs] = useState<LineActions[]>([]);
  const [irSel, setIrSel] = useState<number | null>(null);
  const [menu, setMenu] = useState<{ at: { x: number; y: number }; items: MenuItem[] } | null>(null);
  // One prompt serves every analyst edit: title, prefilled value, and what to
  // do with the answer.
  const [prompt, setPrompt] = useState<{
    title: string;
    value: string;
    hint?: string;
    run: (value: string) => void;
  } | null>(null);
  const [console_, setConsole] = useState(() => loadNum("knife.console", 0) === 1);
  const [renaming, setRenaming] = useState(false);
  const [renameText, setRenameText] = useState("");
  const [noting, setNoting] = useState(false);
  const [noteText, setNoteText] = useState("");

  const curName = functions.find((f) => f.addr === current)?.name ?? current ?? "";

  const openFunction = useCallback(
    async (selector: string, push = true) => {
      try {
        const [ls, irs, graph, la] = await Promise.all([
          api.disassemble(selector),
          api.decompile(selector),
          api.cfg(selector).catch(() => null),
          api.lineActions(selector).catch(() => [] as LineActions[]),
        ]);
        setCfg(graph);
        setActs(la);
        setIrSel(null);
        const entry = ls.length ? ls[0].addr : selector;
        setHistory((h) => (push && current && current !== entry ? [...h, current] : h));
        setLines(ls);
        setIr(irs);
        setSelected(null);
        setNoting(false);
        setRenaming(false);
        setCurrent(entry);
      } catch (e) {
        setError(String(e));
      }
    },
    [current],
  );

  /// Load every view for whichever target is currently active.
  const loadViews = useCallback(async () => {
    const [fns, fnd, det] = await Promise.all([
      api.listFunctions(undefined, false, FN_LIMIT),
      api.attackSurface(),
      api.binaryDetail(),
    ]);
    setFunctions(fns);
    setFindings(fnd);
    setDetail(det);
    api.strings(undefined, true, 5000).then(setStrings).catch(() => setStrings([]));
    return fns;
  }, []);

  const reloadAnalysis = useCallback(async () => {
    try {
      const [fns, fnd, det] = await Promise.all([
        api.listFunctions(filter || undefined, false, FN_LIMIT),
        api.attackSurface(),
        api.binaryDetail(),
      ]);
      setFunctions(fns);
      setFindings(fnd);
      setDetail(det);
    } catch (e) {
      setError(String(e));
    }
  }, [filter]);

  const doOpen = useCallback(
    async (path: string) => {
      setBusy(true);
      setPhase("reading file");
      setError(null);
      try {
        const res = await api.openTarget(path);
        setOpened(res);
        setCurrent(null);
        setSelected(null);
        setLines([]);
        setIr([]);
        setXrefs([]);
        setHistory([]);
        setFilter("");
        const fns = await loadViews();
        api.listTargets().then(setTargets).catch(() => {});
        if (fns.length) void openFunction(fns[0].addr, false);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(false);
        setPhase("");
      }
    },
    [openFunction, loadViews],
  );

  const switchTo = useCallback(
    async (path: string) => {
      try {
        await api.selectTarget(path);
        const res = await api.openTarget(path); // already loaded: just re-reads the summary
        setOpened(res);
        setCurrent(null);
        setSelected(null);
        setLines([]);
        setIr([]);
        setCfg(null);
        setHistory([]);
        setFilter("");
        const fns = await loadViews();
        setTargets(await api.listTargets());
        if (fns.length) void openFunction(fns[0].addr, false);
      } catch (e) {
        setError(String(e));
      }
    },
    [loadViews, openFunction, setError],
  );

  const closeTab = useCallback(
    async (path: string) => {
      try {
        await api.closeTarget(path);
        const rows = await api.listTargets();
        setTargets(rows);
        const next = rows.find((t) => t.active);
        if (next) {
          void switchTo(next.path);
        } else {
          // Nothing left open: back to the welcome screen.
          setOpened(null);
          setFunctions([]);
          setFindings([]);
          setDetail(null);
          setStrings([]);
          setCurrent(null);
          setLines([]);
          setIr([]);
          setCfg(null);
        }
      } catch (e) {
        setError(String(e));
      }
    },
    [switchTo, setError],
  );

  const pickAndOpen = useCallback(async () => {
    const file = await openDialog({ multiple: false, directory: false });
    if (typeof file === "string") void doOpen(file);
  }, [doOpen]);

  useEffect(() => saveNum("knife.leftW", leftW), [leftW]);
  useEffect(() => saveNum("knife.rightW", rightW), [rightW]);
  useEffect(() => saveNum("knife.console", console_ ? 1 : 0), [console_]);

  // The backend names each stage of the load as it starts.
  useEffect(() => {
    const un = listen<string>("knife://phase", (e) => setPhase(e.payload));
    return () => {
      void un.then((f) => f());
    };
  }, []);

  // Imports and exports are fetched when their view is opened, and refetched
  // when the target changes.
  useEffect(() => {
    if (!opened) return;
    if (leftView === "facts") {
      api.analystFacts().then(setFacts).catch(() => setFacts([]));
    } else if (leftView === "patches") {
      api.patchRuns().then(setPatches).catch(() => setPatches([]));
    } else if (leftView === "imports") {
      api.imports().then(setSymbols).catch(() => setSymbols([]));
    } else if (leftView === "exports") {
      api.exports().then(setSymbols).catch(() => setSymbols([]));
    }
  }, [leftView, opened]);

  // Re-filter the function list as the query changes.
  useEffect(() => {
    if (!opened) return;
    api
      .listFunctions(filter || undefined, false, FN_LIMIT)
      .then(setFunctions)
      .catch((e) => setError(String(e)));
  }, [filter, opened]);

  // Load cross-references for the open function whenever it or the direction
  // changes.
  useEffect(() => {
    if (!current) {
      setXrefs([]);
      return;
    }
    api
      .xrefs(current, xrefDir)
      .then(setXrefs)
      .catch(() => setXrefs([]));
  }, [current, xrefDir]);

  // Keyboard map, deliberately the same letters the TUI uses so muscle memory
  // carries between the two front ends. Bare letters are ignored while a text
  // field has focus, or typing a filter would trigger navigation.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement;
      const typing =
        el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement;

      if ((e.ctrlKey || e.metaKey) && (e.key === "p" || e.key === "k")) {
        e.preventDefault();
        setPalette(true);
        return;
      }
      if (e.ctrlKey && (e.key === "`" || e.key === "`")) {
        e.preventDefault();
        setConsole((c) => !c);
        return;
      }
      if (e.key === "Escape") {
        setPalette(false);
        setRenaming(false);
        setNoting(false);
        return;
      }
      if (e.altKey && e.key === "ArrowLeft") {
        e.preventDefault();
        back();
        return;
      }
      if (typing || !opened || prompt || menu) return;

      switch (e.key) {
        case "g":
          e.preventDefault();
          setPalette(true);
          break;
        case "/":
          e.preventDefault();
          setLeftView("functions");
          // Focus happens after the pane has switched.
          setTimeout(() => {
            document.querySelector<HTMLInputElement>(".left .filter input")?.focus();
          }, 0);
          break;
        case "d":
          setTab((t) => (t === "pseudo" ? "disasm" : "pseudo"));
          break;
        case "f":
          setTab((t) => (t === "graph" ? "disasm" : "graph"));
          break;
        case "s":
          setLeftView((v) => {
            const order: LeftView[] = [
              "functions",
              "attack",
              "strings",
              "imports",
              "exports",
              "facts",
              "patches",
            ];
            return order[(order.indexOf(v) + 1) % order.length];
          });
          break;
        case "x":
          setXrefDir((d) => (d === "to" ? "from" : "to"));
          break;
        case "t":
          if (tab === "pseudo" && irSel !== null && acts[irSel]?.field) {
            e.preventDefault();
            editHandlers.bindType(acts[irSel].field!.base);
          }
          break;
        case "e":
          if (tab === "pseudo" && irSel !== null) {
            const f = acts[irSel]?.field;
            if (f?.type_name) {
              e.preventDefault();
              editHandlers.nameField(f.type_name, f.offset, f.member);
            }
          }
          break;
        case "l":
          if (tab === "pseudo" && irSel !== null && acts[irSel]?.variable) {
            e.preventDefault();
            editHandlers.renameVar(acts[irSel].variable!);
          }
          break;
        case "p":
          if (tab === "pseudo" && current) {
            e.preventDefault();
            editHandlers.setPrototype();
          }
          break;
        case "P":
          if (tab === "disasm" && selected) {
            e.preventDefault();
            const line = lines.find((l) => l.kind === "insn" && l.addr === selected);
            ask(
              `Stage bytes at ${selected}`,
              "",
              "hex bytes, empty to restore the run",
              async (v) => {
                try {
                  if (v.trim()) await api.stagePatch(selected, v);
                  else await api.clearPatch(selected);
                  await afterEdit();
                } catch (err) {
                  setError(String(err));
                }
              },
            );
            void line;
          }
          break;
        case "n":
          if (current) {
            e.preventDefault();
            setRenameText(curName);
            setRenaming(true);
          }
          break;
        case "c":
          if (current) {
            e.preventDefault();
            setNoteText("");
            setNoting(true);
          }
          break;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  /// Re-read the current function after an analyst edit, so the pseudocode
  /// shows the new type, name, or prototype immediately.
  const afterEdit = useCallback(async () => {
    await reloadAnalysis();
    if (current) await openFunction(current, false);
    // The fact inventory and the patch list are what an edit changed, so keep
    // them current whether or not their pane happens to be open.
    api.analystFacts().then(setFacts).catch(() => {});
    api.patchRuns().then(setPatches).catch(() => {});
  }, [reloadAnalysis, current, openFunction]);

  const ask = useCallback(
    (title: string, value: string, hint: string, run: (v: string) => void) =>
      setPrompt({ title, value, hint, run }),
    [],
  );

  const editHandlers = useMemo(
    () => ({
      bindType: (base: string) =>
        ask(`Bind a type to ${base}`, "", "a type name, empty to clear", async (v) => {
          try {
            if (!current) return;
            if (v.trim()) await api.bindType(current, base, v);
            else await api.clearBinding(current, base);
            await afterEdit();
          } catch (e) {
            setError(String(e));
          }
        }),
      nameField: (typeName: string, offset: number, member: string) =>
        ask(
          `Name ${typeName} field at ${offset < 0 ? "-" : "+"}0x${Math.abs(offset).toString(16)}`,
          member.startsWith("field_") ? "" : member,
          "a field name, empty to clear",
          async (v) => {
            try {
              if (v.trim()) await api.setField(typeName, offset, v);
              else await api.clearField(typeName, offset);
              await afterEdit();
            } catch (e) {
              setError(String(e));
            }
          },
        ),
      renameVar: (base: string) =>
        ask(`Rename ${base}`, "", "a variable name, empty to clear", async (v) => {
          try {
            if (!current) return;
            if (v.trim()) await api.setVariable(current, base, v);
            else await api.clearVariable(current, base);
            await afterEdit();
          } catch (e) {
            setError(String(e));
          }
        }),
      setPrototype: () =>
        ask("Prototype", "", "RETURN (PARAM, PARAM), empty to clear", async (v) => {
          try {
            if (!current) return;
            const text = v.trim();
            if (!text) {
              await api.clearPrototype(current);
            } else {
              // `bool (CONTEXT *, size_t)` splits into a return type and a
              // parameter list, the same syntax the terminal interface takes.
              const open = text.indexOf("(");
              const returns = (open < 0 ? text : text.slice(0, open)).trim();
              const inner = open < 0 ? "" : text.slice(open + 1).replace(/\)\s*$/, "");
              const params = inner
                .split(",")
                .map((p) => p.trim())
                .filter(Boolean);
              await api.setPrototype(current, returns, params);
            }
            await afterEdit();
          } catch (e) {
            setError(String(e));
          }
        }),
    }),
    [ask, current, afterEdit, setError],
  );

  const back = useCallback(() => {
    setHistory((h) => {
      if (!h.length) return h;
      void openFunction(h[h.length - 1], false);
      return h.slice(0, -1);
    });
  }, [openFunction]);

  const submitRename = useCallback(async () => {
    if (!current) return;
    const name = renameText.trim();
    setRenaming(false);
    if (!name || name === curName) return;
    try {
      await api.setName(current, name);
      await reloadAnalysis();
      await openFunction(current, false);
    } catch (e) {
      setError(String(e));
    }
  }, [current, renameText, curName, reloadAnalysis, openFunction]);

  const submitNote = useCallback(async () => {
    const at = selected ?? current;
    const note = noteText.trim();
    setNoting(false);
    if (!at || !note) return;
    try {
      await api.setNote(at, note);
      if (current) await openFunction(current, false);
    } catch (e) {
      setError(String(e));
    }
  }, [selected, current, noteText, openFunction]);

  return (
    <div className="app">
      <div className="topbar">
        <span className="brand">
          <span className="slash">╱</span> KNIFE
        </span>
        {opened && (
          <span className="topmeta">
            <b>{opened.title}</b> · {opened.format} · {opened.arch} · {opened.functions} functions ·{" "}
            {opened.high_risk} high-risk{opened.is_driver ? " · driver" : ""}
          </span>
        )}
        <div className="spacer" />
        <button className="btn" onClick={pickAndOpen} disabled={busy}>
          {busy ? "analyzing…" : "Open binary"}
        </button>
      </div>

      {targets.length > 0 && (
        <div className="tabbar">
          {targets.map((t) => (
            <div
              key={t.path}
              className={"ttab" + (t.active ? " active" : "")}
              title={t.path}
              onClick={() => !t.active && switchTo(t.path)}
            >
              <span className="tname">{t.title}</span>
              <span
                className="tclose"
                title="Close"
                onClick={(e) => {
                  e.stopPropagation();
                  void closeTab(t.path);
                }}
              >
                ✕
              </span>
            </div>
          ))}
        </div>
      )}

      <div className="body">
        <div className="rail">
          <button
            className={leftView === "functions" ? "active" : ""}
            title="Functions"
            onClick={() => setLeftView("functions")}
          >
            ƒ
          </button>
          <button
            className={leftView === "attack" ? "active" : ""}
            title="Attack surface"
            onClick={() => setLeftView("attack")}
          >
            ⚠
          </button>
          <button
            className={leftView === "strings" ? "active" : ""}
            title="Strings"
            onClick={() => setLeftView("strings")}
          >
            T
          </button>
          <button
            className={leftView === "imports" ? "active" : ""}
            title="Imports"
            onClick={() => setLeftView("imports")}
          >
            ↓
          </button>
          <button
            className={leftView === "exports" ? "active" : ""}
            title="Exports"
            onClick={() => setLeftView("exports")}
          >
            ↑
          </button>
          <button
            className={leftView === "facts" ? "active" : ""}
            title="Types and analyst facts"
            onClick={() => setLeftView("facts")}
          >
            {"{}"}
          </button>
          <button
            className={leftView === "patches" ? "active" : ""}
            title="Staged patches"
            onClick={() => setLeftView("patches")}
          >
            ±
          </button>
          <button
            className={console_ ? "active" : ""}
            title="Console (ctrl+`)"
            onClick={() => setConsole((c) => !c)}
          >
            &gt;_
          </button>
          <div className="spacer" />
          <button title="Back" onClick={back} disabled={!history.length}>
            ‹
          </button>
        </div>

        {!opened ? (
          <div className="welcome">
            <div>
              <div className="big">╱ knife</div>
              <div className="sub">Find the bug, not just the binary.</div>
              <div style={{ marginTop: 16 }}>
                <button className="btn" onClick={pickAndOpen}>
                  Open a PE / ELF / Mach-O
                </button>
              </div>
            </div>
          </div>
        ) : (
          <>
            <div className="panel left" style={{ width: leftW, flex: `0 0 ${leftW}px` }}>
              {leftView === "functions" ? (
                <>
                  <div className="panel-head">
                    <span>functions</span>
                    <span className="count">({functions.length})</span>
                  </div>
                  <div className="filter">
                    <input
                      placeholder="filter…"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    />
                  </div>
                  <FunctionList rows={functions} current={current} onPick={(a) => openFunction(a)} />
                </>
              ) : leftView === "facts" ? (
                <>
                  <div className="panel-head">
                    <span>analyst facts</span>
                    <span className="count">({facts.length})</span>
                  </div>
                  <div className="filter">
                    <input
                      placeholder="filter types, prototypes, bindings…"
                      onChange={(e) =>
                        api
                          .analystFacts(e.target.value || undefined)
                          .then(setFacts)
                          .catch(() => setFacts([]))
                      }
                    />
                  </div>
                  <FactsList rows={facts} onJump={(a) => openFunction(a)} />
                </>
              ) : leftView === "patches" ? (
                <>
                  <div className="panel-head">
                    <span>staged patches</span>
                    <span className="count">({patches.length})</span>
                  </div>
                  <PatchList
                    runs={patches}
                    onJump={(a) => openFunction(a)}
                    onClear={async (offset) => {
                      try {
                        await api.clearPatch(offset);
                        await afterEdit();
                      } catch (e) {
                        setError(String(e));
                      }
                    }}
                    onExport={async () => {
                      const out = await saveDialog({ title: "Export patched binary" });
                      if (typeof out !== "string") return;
                      try {
                        const msg = await api.exportPatched(out);
                        setToasts((t) => [...t, { id: Date.now(), text: msg }]);
                      } catch (e) {
                        setError(String(e));
                      }
                    }}
                  />
                </>
              ) : leftView === "imports" || leftView === "exports" ? (
                <>
                  <div className="panel-head">
                    <span>{leftView}</span>
                    <span className="count">({symbols.length})</span>
                  </div>
                  <div className="filter">
                    <input
                      placeholder={`filter ${leftView}…`}
                      onChange={(e) => {
                        const q = e.target.value || undefined;
                        const call = leftView === "imports" ? api.imports : api.exports;
                        call(q).then(setSymbols).catch(() => setSymbols([]));
                      }}
                    />
                  </div>
                  <SymbolList
                    rows={symbols}
                    showModules={leftView === "imports"}
                    onJump={(a) => openFunction(a)}
                  />
                </>
              ) : leftView === "strings" ? (
                <>
                  <div className="panel-head">
                    <span>strings</span>
                    <span className="count">({strings.length})</span>
                  </div>
                  <div className="filter">
                    <input
                      placeholder="filter literals…"
                      onChange={(e) => {
                        const q = e.target.value;
                        api
                          .strings(q || undefined, !q, 5000)
                          .then(setStrings)
                          .catch(() => setStrings([]));
                      }}
                    />
                  </div>
                  <StringsList rows={strings} onJump={(a) => openFunction(a)} />
                </>
              ) : (
                <>
                  <div className="panel-head">
                    <span>attack surface</span>
                    <span className="count">({findings.length})</span>
                  </div>
                  <AttackSurface
                    findings={findings}
                    selected={selected}
                    onPick={(f) => {
                      setSelected(f.addr);
                      void openFunction(f.addr);
                    }}
                  />
                </>
              )}
            </div>

            <Divider onDrag={(dx) => setLeftW((w) => Math.min(700, Math.max(220, w + dx)))} />
            <div className="center">
              <div className="tabs">
                <div
                  className={"tab" + (tab === "disasm" ? " active" : "")}
                  onClick={() => setTab("disasm")}
                >
                  disassembly
                </div>
                <div
                  className={"tab" + (tab === "pseudo" ? " active" : "")}
                  onClick={() => setTab("pseudo")}
                >
                  pseudocode
                </div>
                <div
                  className={"tab" + (tab === "graph" ? " active" : "")}
                  onClick={() => setTab("graph")}
                >
                  graph
                </div>
                <div className="title">
                  {renaming ? (
                    <input
                      className="inline-input"
                      autoFocus
                      style={{ width: 220 }}
                      value={renameText}
                      onChange={(e) => setRenameText(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void submitRename();
                        if (e.key === "Escape") setRenaming(false);
                      }}
                      onBlur={() => setRenaming(false)}
                    />
                  ) : (
                    <span className="fname">{curName}</span>
                  )}
                  <button
                    className="act"
                    disabled={!current}
                    onClick={() => {
                      setRenameText(curName);
                      setRenaming(true);
                    }}
                  >
                    rename
                  </button>
                  <button
                    className="act"
                    disabled={!current}
                    onClick={() => {
                      setNoteText("");
                      setNoting((n) => !n);
                    }}
                  >
                    note
                  </button>
                </div>
              </div>

              {noting && (
                <div className="filter">
                  <input
                    className="inline-input"
                    autoFocus
                    placeholder={
                      selected ? `note on ${selected}` : "select an instruction, then type a note"
                    }
                    value={noteText}
                    onChange={(e) => setNoteText(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void submitNote();
                      if (e.key === "Escape") setNoting(false);
                    }}
                  />
                </div>
              )}

              {tab === "graph" ? (
                <GraphView cfg={cfg} onOpenBlock={(a) => { setTab("disasm"); setSelected(a); }} />
              ) : (
                <CodeView
                  tab={tab}
                  lines={lines}
                  ir={ir}
                  selected={selected}
                  irSelected={irSel}
                  onSelect={setSelected}
                  onSelectIr={setIrSel}
                  onFollow={(sel) => openFunction(sel)}
                  onLineMenu={(i, at) =>
                    setMenu({ at, items: pseudoMenu(acts[i], editHandlers) })
                  }
                />
              )}

              <XrefPane rows={xrefs} dir={xrefDir} onDir={setXrefDir} onJump={(a) => openFunction(a)} />
            </div>

            <Divider onDrag={(dx) => setRightW((w) => Math.min(720, Math.max(240, w - dx)))} />
            <div className="right" style={{ width: rightW, flex: `0 0 ${rightW}px` }}>
              {detail && <DetailPanel d={detail} />}
            </div>
          </>
        )}
      </div>

      {opened && console_ && (
        <Console onClose={() => setConsole(false)} onJump={(a) => openFunction(a)} />
      )}

      {opened && (
        <div className="statusbar">
          <span className="sb-fn">{curName || "—"}</span>
          {(() => {
            const f = functions.find((x) => x.addr === current);
            return f ? (
              <span className="sb-meta">
                {f.blocks} blocks · {f.size} bytes · {f.incoming} refs
              </span>
            ) : null;
          })()}
          <div className="spacer" />
          <span className="sb-keys">
            ctrl+p open   ctrl+` console   g goto   / filter   d pseudo   f graph   s pane   x xrefs   n name   c note   t type   e field   l var   p proto   P patch
          </span>
        </div>
      )}

      {toasts.length > 0 && (
        <div className="toasts">
          {toasts.map((t) => (
            <div
              key={t.id}
              className="toast"
              onClick={() => setToasts((all) => all.filter((x) => x.id !== t.id))}
            >
              {t.text}
            </div>
          ))}
        </div>
      )}

      {busy && (
        <div className="overlay loading">
          <div className="loadbox">
            <div className="spinner" />
            <div className="lphase">{phase || "analyzing"}…</div>
            <div className="lhint">reading the bytes on disk · the target is never executed</div>
          </div>
        </div>
      )}

      {menu && (
        <LineMenu at={menu.at} items={menu.items} onClose={() => setMenu(null)} />
      )}

      {prompt && (
        <div className="overlay" onMouseDown={() => setPrompt(null)}>
          <div className="askbox" onMouseDown={(e) => e.stopPropagation()}>
            <div className="asktitle">{prompt.title}</div>
            <input
              className="palette-input"
              autoFocus
              defaultValue={prompt.value}
              placeholder={prompt.hint}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  const v = (e.target as HTMLInputElement).value;
                  setPrompt(null);
                  prompt.run(v);
                } else if (e.key === "Escape") {
                  setPrompt(null);
                }
              }}
            />
            <div className="askfoot">
              <span>{prompt.hint}</span>
              <span>↵ apply</span>
              <span>esc cancel</span>
            </div>
          </div>
        </div>
      )}

      {palette && (
        <Palette
          functions={functions}
          onPick={(sel) => openFunction(sel)}
          onClose={() => setPalette(false)}
        />
      )}
    </div>
  );
}
