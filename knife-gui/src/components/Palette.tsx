import { useEffect, useMemo, useRef, useState } from "react";
import type { FnRow } from "../api";

/**
 * Quick-open: type to find a function, or paste an address to jump straight to
 * it. Reverse engineering is keyboard work — hunting a name in a list of forty
 * thousand with the mouse is the slow path.
 *
 * Matching is subsequence-based, so `dsp` finds `DispatchDeviceControl`, and
 * results are ranked: exact, then prefix, then contiguous substring, then a
 * scattered subsequence. Named functions win ties, because a name someone
 * bothered to write is more likely the one being looked for than `sub_1400a2c0`.
 */
function score(name: string, q: string): number | null {
  const n = name.toLowerCase();
  if (!q) return 0;
  if (n === q) return 1000;
  if (n.startsWith(q)) return 800 - n.length;
  const at = n.indexOf(q);
  if (at >= 0) return 600 - at - n.length / 100;
  // Scattered subsequence: every character in order, anywhere.
  let i = 0;
  let gaps = 0;
  let last = -1;
  for (let k = 0; k < n.length && i < q.length; k++) {
    if (n[k] === q[i]) {
      if (last >= 0) gaps += k - last - 1;
      last = k;
      i++;
    }
  }
  return i === q.length ? 300 - gaps : null;
}

const MAX_ROWS = 200;

export function Palette({
  functions,
  onPick,
  onClose,
}: {
  functions: FnRow[];
  onPick: (selector: string) => void;
  onClose: () => void;
}) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // A bare hex value is an address to jump to, not a name to search for.
  const asAddress = useMemo(() => {
    const t = q.trim().replace(/^0x/i, "");
    return t.length >= 4 && /^[0-9a-f]+$/i.test(t) ? "0x" + t.toLowerCase() : null;
  }, [q]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const scored: Array<{ f: FnRow; s: number }> = [];
    for (const f of functions) {
      const s = score(f.name, needle);
      if (s !== null) scored.push({ f, s: s + (f.named ? 40 : 0) });
    }
    scored.sort((a, b) => b.s - a.s);
    return scored.slice(0, MAX_ROWS).map((x) => x.f);
  }, [functions, q]);

  useEffect(() => setSel(0), [q]);

  // Keep the highlighted row in view as the selection moves.
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-i="${sel}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const choose = (i: number) => {
    if (asAddress && i === 0) {
      onPick(asAddress);
      onClose();
      return;
    }
    const f = rows[asAddress ? i - 1 : i];
    if (f) {
      onPick(f.addr);
      onClose();
    }
  };

  const total = rows.length + (asAddress ? 1 : 0);

  return (
    <div className="overlay" onMouseDown={onClose}>
      <div className="palette" onMouseDown={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="palette-input"
          placeholder="function name, or an address…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") onClose();
            else if (e.key === "ArrowDown") {
              e.preventDefault();
              setSel((s) => Math.min(total - 1, s + 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setSel((s) => Math.max(0, s - 1));
            } else if (e.key === "Enter") {
              e.preventDefault();
              choose(sel);
            }
          }}
        />
        <div className="palette-rows" ref={listRef}>
          {asAddress && (
            <div
              data-i={0}
              className={"palette-row" + (sel === 0 ? " sel" : "")}
              onClick={() => choose(0)}
            >
              <span className="goto">go to</span>
              <span className="nm">{asAddress}</span>
            </div>
          )}
          {rows.map((f, i) => {
            const idx = asAddress ? i + 1 : i;
            return (
              <div
                key={f.addr}
                data-i={idx}
                className={"palette-row" + (sel === idx ? " sel" : "")}
                onClick={() => choose(idx)}
              >
                <span className="addr">{f.addr.replace("0x", "")}</span>
                <span className={"nm" + (f.named ? " named" : "")}>{f.name}</span>
                <span className="refs">{f.incoming}</span>
              </div>
            );
          })}
          {total === 0 && <div className="palette-row empty">no match</div>}
        </div>
        <div className="palette-foot">
          <span>↑↓ move</span>
          <span>↵ open</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  );
}
