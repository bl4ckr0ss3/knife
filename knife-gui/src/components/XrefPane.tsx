import type { XrefRow } from "../api";

export function XrefPane({
  rows,
  dir,
  onDir,
  onJump,
}: {
  rows: XrefRow[];
  dir: "to" | "from";
  onDir: (d: "to" | "from") => void;
  onJump: (addr: string) => void;
}) {
  return (
    <div className="xref">
      <div className="panel-head">
        <span>xrefs</span>
        <span className="count">({rows.length})</span>
        <div className="spacer" />
        <div className="seg">
          <button className={dir === "to" ? "active" : ""} onClick={() => onDir("to")}>
            callers
          </button>
          <button className={dir === "from" ? "active" : ""} onClick={() => onDir("from")}>
            callees
          </button>
        </div>
      </div>
      <div className="rows">
        {rows.length === 0 && (
          <div className="xref-row" style={{ color: "var(--faint)" }}>
            no {dir === "to" ? "references" : "calls"}
          </div>
        )}
        {rows.map((r, i) => (
          <div key={i} className="xref-row" onClick={() => onJump(r.addr)}>
            <span className="addr">{r.addr.replace("0x", "")}</span>
            <span className="k">{r.kind}</span>
            <span className="nm">{r.site}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
