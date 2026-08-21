import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { StringRow } from "../api";

// Literals, with how many instructions point at each. A referenced string is
// the fastest route into unfamiliar code, so the reference count leads.
export function StringsList({
  rows,
  onJump,
}: {
  rows: StringRow[];
  onJump: (addr: string) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 22,
    overscan: 20,
  });

  return (
    <div className="list" ref={parentRef}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {v.getVirtualItems().map((item) => {
          const s = rows[item.index];
          return (
            <div
              key={s.addr}
              className="fn-row"
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                height: item.size,
                transform: `translateY(${item.start}px)`,
              }}
              title={s.text}
              onClick={() => s.refs > 0 && onJump(s.addr)}
            >
              <span className="addr">{s.addr.replace("0x", "")}</span>
              <span className={"nm" + (s.wide ? " wide" : "")}>{s.text}</span>
              <span className="refs">{s.refs || ""}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
