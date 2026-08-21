import { useEffect, useRef, useState } from "react";
import { api, type ConsoleLine } from "../api";

/**
 * The command console.
 *
 * Keeps its own scrollback and history: an analyst's session is a trail of
 * questions, and being able to press Up and re-ask the last one — or scroll
 * back to what the answer was — is most of the value of having a console at all.
 */
export function Console({
  onClose,
  onJump,
}: {
  onClose: () => void;
  onJump: (addr: string) => void;
}) {
  const [lines, setLines] = useState<ConsoleLine[]>([
    { kind: "hint", text: "knife console · type `help` for commands" },
  ]);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [, setHistAt] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [lines]);

  const run = async () => {
    const cmd = input.trim();
    if (!cmd || busy) return;
    setInput("");
    setHistory((h) => [...h, cmd]);
    setHistAt(null);

    if (cmd === "clear") {
      setLines([]);
      return;
    }
    setLines((l) => [...l, { kind: "cmd", text: cmd }]);
    setBusy(true);
    try {
      const out = await api.consoleExec(cmd);
      setLines((l) => [...l, ...out]);
    } catch (e) {
      setLines((l) => [...l, { kind: "err", text: String(e) }]);
    } finally {
      setBusy(false);
    }
  };

  // An address anywhere in an output line is clickable — the console is a way
  // into the code, not just a place that prints about it.
  const renderLine = (l: ConsoleLine, i: number) => {
    if (l.kind !== "out") {
      return (
        <div key={i} className={"cline " + l.kind}>
          {l.kind === "cmd" ? "$ " + l.text : l.text}
        </div>
      );
    }
    const parts = l.text.split(/(0x[0-9a-f]{4,})/gi);
    return (
      <div key={i} className="cline out">
        {parts.map((p, j) =>
          /^0x[0-9a-f]{4,}$/i.test(p) ? (
            <span key={j} className="caddr" onClick={() => onJump(p)}>
              {p}
            </span>
          ) : (
            <span key={j}>{p}</span>
          ),
        )}
      </div>
    );
  };

  return (
    <div className="console">
      <div className="panel-head">
        <span>console</span>
        {busy && <span className="count">working…</span>}
        <div className="spacer" />
        <button className="act" onClick={() => setLines([])} title="Clear">
          clear
        </button>
        <button className="act" onClick={onClose} title="Close (ctrl+`)">
          ✕
        </button>
      </div>

      <div className="cout">
        {lines.map(renderLine)}
        <div ref={endRef} />
      </div>

      <div className="cin">
        <span className="prompt">$</span>
        <input
          ref={inputRef}
          className="inline-input"
          placeholder="info · funcs · audit · strings · xrefs · dis · pseudo"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              void run();
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setHistAt((at) => {
                const next = at === null ? history.length - 1 : Math.max(0, at - 1);
                if (history[next] !== undefined) setInput(history[next]);
                return next;
              });
            } else if (e.key === "ArrowDown") {
              e.preventDefault();
              setHistAt((at) => {
                if (at === null) return null;
                const next = at + 1;
                if (next >= history.length) {
                  setInput("");
                  return null;
                }
                setInput(history[next]);
                return next;
              });
            } else if (e.key === "Escape") {
              onClose();
            }
          }}
        />
      </div>
    </div>
  );
}
