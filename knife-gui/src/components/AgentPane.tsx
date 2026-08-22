import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, type AgentStep, type ChatMessage, type Suggestion } from "../api";
import { Markdown } from "./Markdown";

export type AgentDock = "bottom" | "left" | "right";

interface Turn {
  question: string;
  reply: string;
  steps: AgentStep[];
  suggestions: Suggestion[];
}

interface Live {
  question: string;
  reply: string;
  steps: AgentStep[];
  suggestions: Suggestion[];
  status: string;
}

type AgentEvent =
  | { kind: "round" }
  | { kind: "token"; text: string }
  | { kind: "tool"; tool: string; args: string }
  | { kind: "result"; tool: string; preview: string }
  | { kind: "suggestion"; suggestion: Suggestion }
  | { kind: "done" };

const chatKey = (target: string) => `knife.agent.chat.${target}`;

function loadChat(target: string): { turns: Turn[]; history: ChatMessage[] } {
  try {
    const raw = localStorage.getItem(chatKey(target));
    if (raw) return JSON.parse(raw);
  } catch {
    // a cleared or corrupt store just starts an empty chat
  }
  return { turns: [], history: [] };
}

/**
 * The agent pane.
 *
 * The model reads this binary through knife's tools, and the turn streams: each
 * tool call appears as it is made, and the answer types itself. Replies render
 * as markdown so a returned table is a table; addresses stay clickable. It is
 * read-only — it can propose a rename or a prototype, and applying one is your
 * click, never its own.
 */
export function AgentPane({
  enabled,
  consented,
  targetName,
  targetKey,
  isDriver,
  hasKey,
  model,
  dock,
  onModel,
  onDock,
  onConsent,
  onNeedKey,
  onClose,
  onJump,
  onApply,
}: {
  enabled: boolean;
  consented: boolean;
  targetName: string;
  targetKey: string;
  isDriver: boolean;
  hasKey: boolean;
  model: string;
  dock: AgentDock;
  onModel: (m: string) => void;
  onDock: (d: AgentDock) => void;
  onConsent: () => void;
  onNeedKey: () => void;
  onClose: () => void;
  onJump: (addr: string) => void;
  onApply: (s: Suggestion) => Promise<void>;
}) {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [history, setHistory] = useState<ChatMessage[]>([]);
  const [applied, setApplied] = useState<Set<string>>(new Set());
  const [live, setLive] = useState<Live | null>(null);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const liveRef = useRef(false);

  // Load the conversation for this binary, and reload when the binary changes.
  useEffect(() => {
    const { turns, history } = loadChat(targetKey);
    setTurns(turns);
    setHistory(history);
    setApplied(new Set());
    setLive(null);
    liveRef.current = false;
  }, [targetKey]);

  // Persist after every completed turn.
  useEffect(() => {
    if (!targetKey) return;
    try {
      localStorage.setItem(chatKey(targetKey), JSON.stringify({ turns, history }));
    } catch {
      // remembering the chat is a convenience, not a requirement
    }
  }, [turns, history, targetKey]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [turns, live]);

  useEffect(() => {
    const un = listen<AgentEvent>("knife://agent", (e) => {
      if (!liveRef.current) return;
      const ev = e.payload;
      setLive((l) => {
        if (!l) return l;
        switch (ev.kind) {
          case "round":
            return { ...l, status: "thinking" };
          case "token":
            return { ...l, reply: l.reply + ev.text, status: "" };
          case "tool":
            return {
              ...l,
              status: `reading ${ev.tool}`,
              steps: [...l.steps, { tool: ev.tool, args: ev.args, preview: "" }],
            };
          case "result": {
            const steps = l.steps.slice();
            for (let i = steps.length - 1; i >= 0; i--) {
              if (steps[i].tool === ev.tool && !steps[i].preview) {
                steps[i] = { ...steps[i], preview: ev.preview };
                break;
              }
            }
            return { ...l, steps, status: "thinking" };
          }
          case "suggestion":
            return { ...l, suggestions: [...l.suggestions, ev.suggestion] };
          case "done":
            return { ...l, status: "" };
        }
      });
    });
    return () => {
      void un.then((f) => f());
    };
  }, []);

  const ask = async () => {
    const q = input.trim();
    if (!q || liveRef.current) return;
    setInput("");
    setError(null);
    setLive({ question: q, reply: "", steps: [], suggestions: [], status: "thinking" });
    liveRef.current = true;
    try {
      const t = await api.agentAsk(model, q, history);
      setTurns((all) => [
        ...all,
        { question: q, reply: t.reply, steps: t.steps, suggestions: t.suggestions },
      ]);
      setHistory(t.history);
    } catch (e) {
      setError(String(e));
    } finally {
      liveRef.current = false;
      setLive(null);
    }
  };

  const newChat = () => {
    setTurns([]);
    setHistory([]);
    setApplied(new Set());
    try {
      localStorage.removeItem(chatKey(targetKey));
    } catch {
      /* ignore */
    }
  };

  const stepArgs = (raw: string): string => {
    try {
      const o = JSON.parse(raw || "{}");
      const parts = Object.entries(o)
        .map(([k, v]) => {
          const val = String(v);
          const short = val.length > 22 ? val.slice(0, 21) + "…" : val;
          // A single obvious argument reads better without its key.
          return k === "selector" || k === "query" ? short : `${k} ${short}`;
        })
        .filter(Boolean);
      return parts.join("  ");
    } catch {
      return "";
    }
  };

  const renderSteps = (steps: AgentStep[]) =>
    steps.length > 0 && (
      <div className="steps">
        {steps.map((s, j) => (
          <div className="step" key={j} title={s.preview}>
            <span className="stool">{s.tool}</span>
            {stepArgs(s.args) && <span className="sargs">{stepArgs(s.args)}</span>}
          </div>
        ))}
      </div>
    );

  const suggestionLabel = (s: Suggestion) =>
    s.kind === "rename"
      ? `rename ${s.selector} → ${s.new_name}`
      : `prototype ${s.selector}: ${s.returns} (${(s.params ?? []).join(", ")})`;

  const renderSuggestions = (list: Suggestion[]) =>
    list.length > 0 && (
      <div className="suggestions">
        {list.map((s, j) => {
          const id = `${s.kind}:${s.selector}:${s.new_name ?? ""}:${s.returns ?? ""}`;
          const done = applied.has(id);
          return (
            <div className="suggestion" key={j} title={s.reason}>
              <span className="sug-kind">{s.kind}</span>
              <span className="sug-text">{suggestionLabel(s)}</span>
              {done ? (
                <span className="sug-done">applied</span>
              ) : (
                <button
                  className="sug-apply"
                  onClick={async () => {
                    try {
                      await onApply(s);
                      setApplied((prev) => new Set(prev).add(id));
                    } catch (e) {
                      setError(String(e));
                    }
                  }}
                >
                  apply
                </button>
              )}
            </div>
          );
        })}
      </div>
    );

  const examples = isDriver
    ? [
        "Map the IOCTL attack surface and flag any LPE primitive.",
        "Is there an arbitrary read/write reachable from an IOCTL?",
        "Which handler runs with no ProbeForRead on the input buffer?",
      ]
    : [
        "What does this binary do?",
        "Explain the worst audit finding and whether it is reachable.",
        "Which functions parse untrusted input?",
      ];

  return (
    <div className={`agent dock-${dock}`}>
      <div className="panel-head">
        <span>agent</span>
        {isDriver && <span className="agent-mode">LPE hunt</span>}
        <div className="spacer" />
        <span className="dock-controls" title="Dock position">
          {(["left", "bottom", "right"] as AgentDock[]).map((d) => (
            <button
              key={d}
              className={"dockbtn" + (dock === d ? " on" : "")}
              title={`dock ${d}`}
              onClick={() => onDock(d)}
            >
              {d === "left" ? "▏" : d === "right" ? "▕" : "▁"}
            </button>
          ))}
        </span>
        {(turns.length > 0 || history.length > 0) && !live && (
          <button className="act" onClick={newChat}>
            new chat
          </button>
        )}
        <button className="act" onClick={onClose}>
          ✕
        </button>
      </div>

      {!enabled ? (
        <div className="agent-gate">
          <p>The agent is switched off.</p>
          <p className="sub">Turn it on in the top bar to use it on any binary.</p>
        </div>
      ) : !hasKey ? (
        <div className="agent-gate">
          <p>No OpenRouter key stored.</p>
          <p className="sub">
            The key is kept in Windows Credential Manager, not in a file or this repo.
          </p>
          <button className="btn" onClick={onNeedKey}>
            Add key
          </button>
        </div>
      ) : !consented ? (
        <div className="agent-gate warn">
          <p>Code from this binary would be sent to OpenRouter.</p>
          <p className="sub">
            Disassembly, pseudocode and strings from <b>{targetName}</b> leave your machine when you
            ask a question. Fine for your own binaries; think twice for someone else's.
          </p>
          <button className="btn" onClick={onConsent}>
            Enable for this binary
          </button>
        </div>
      ) : (
        <>
          <div className="agent-log">
            {turns.length === 0 && !live && (
              <div className="agent-hint">
                {isDriver
                  ? "Driver loaded. Ask it to hunt a privilege-escalation primitive; it reads the IOCTL surface with knife's tools and shows every call."
                  : "Ask about the open binary. The model reads it with knife's tools and shows every call it makes."}
                <div className="agent-eg">
                  {examples.map((ex) => (
                    <span key={ex} onClick={() => setInput(ex)}>
                      {ex}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {turns.map((t, i) => (
              <div className="turn" key={i}>
                <div className="q">{t.question}</div>
                {renderSteps(t.steps)}
                <div className="a">
                  <Markdown text={t.reply} onJump={onJump} />
                </div>
                {renderSuggestions(t.suggestions)}
              </div>
            ))}

            {live && (
              <div className="turn">
                <div className="q">{live.question}</div>
                {renderSteps(live.steps)}
                {live.reply && <div className="a streaming">{live.reply}</div>}
                {renderSuggestions(live.suggestions)}
                {live.status && (
                  <div className="agent-busy">
                    <span className="dot" />
                    {live.status}…
                    <button className="stopbtn" onClick={() => void api.agentCancel()}>
                      stop
                    </button>
                  </div>
                )}
              </div>
            )}

            {error && <div className="agent-err">{error}</div>}
            <div ref={endRef} />
          </div>

          <div className="cin">
            <span className="prompt">?</span>
            <input
              className="inline-input"
              placeholder={live ? "working…" : "ask about this binary"}
              value={input}
              disabled={!!live}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void ask();
                } else if (e.key === "Escape") {
                  onClose();
                }
              }}
            />
            <input
              className="agent-model"
              value={model}
              onChange={(e) => onModel(e.target.value)}
              title="OpenRouter model id"
            />
          </div>
        </>
      )}
    </div>
  );
}
