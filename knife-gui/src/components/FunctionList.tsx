import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { FnRow } from "../api";

// A large image recovers tens of thousands of functions, so the list is
// virtualized: only the visible rows exist in the DOM.
export function FunctionList({
  rows,
  current,
  onPick,
}: {
  rows: FnRow[];
  current: string | null;
  onPick: (addr: string) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 22,
    overscan: 24,
  });

  return (
    <div className="list" ref={parentRef}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {v.getVirtualItems().map((item) => {
          const f = rows[item.index];
          return (
            <div
              key={f.addr}
              className={"fn-row" + (f.addr === current ? " sel" : "")}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                height: item.size,
                transform: `translateY(${item.start}px)`,
              }}
              onClick={() => onPick(f.addr)}
              title={`${f.name}  ${f.blocks} blocks  ${f.size} bytes`}
            >
              <span className="addr">{f.addr.replace("0x", "")}</span>
              <span className={"nm" + (f.named ? " named" : "")}>{f.name}</span>
              <span className="refs">{f.incoming}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
