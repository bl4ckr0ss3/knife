import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { SymbolRow } from "../api";

type Item =
  | { type: "module"; module: string }
  | { type: "sym"; row: SymbolRow };

/**
 * Imports or exports.
 *
 * Imports arrive grouped by module and ordered by reference count, because the
 * API a binary calls two hundred times says far more about what it does than
 * the one it merely names. Module headers are flattened into the row list
 * rather than nested, so the whole thing can be virtualised as one sequence —
 * a system DLL can import several thousand symbols.
 */
export function SymbolList({
  rows,
  showModules,
  onJump,
}: {
  rows: SymbolRow[];
  showModules: boolean;
  onJump: (addr: string) => void;
}) {
  const items = useMemo<Item[]>(() => {
    const out: Item[] = [];
    let module: string | null = null;
    for (const row of rows) {
      if (showModules && row.module && row.module !== module) {
        module = row.module;
        out.push({ type: "module", module });
      }
      out.push({ type: "sym", row });
    }
    return out;
  }, [rows, showModules]);

  const parentRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (i) => (items[i].type === "module" ? 24 : 22),
    overscan: 20,
  });

  return (
    <div className="list" ref={parentRef}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {v.getVirtualItems().map((item) => {
          const it = items[item.index];
          const style = {
            position: "absolute" as const,
            top: 0,
            left: 0,
            right: 0,
            height: item.size,
            transform: `translateY(${item.start}px)`,
          };
          if (it.type === "module") {
            return (
              <div key={"m" + item.index} style={style} className="sym-module">
                {it.module}
              </div>
            );
          }
          const s = it.row;
          return (
            <div
              key={"s" + item.index}
              style={style}
              className={"fn-row" + (s.addr ? "" : " dim")}
              title={s.module ? `${s.module}!${s.name}` : s.name}
              onClick={() => s.addr && onJump(s.addr)}
            >
              <span className="nm">{s.name}</span>
              <span className="refs">{s.refs || ""}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
