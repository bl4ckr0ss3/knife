import type { PathRow, XrefRow } from "../api";

export type RefMode = "to" | "from" | "paths";

export function XrefPane({
  rows,
  paths,
  dir,
  onDir,
  onJump,
}: {
  rows: XrefRow[];
  paths: PathRow[];
  dir: RefMode;
  onDir: (d: RefMode) => void;
  onJump: (addr: string) => void;
}) {
  return (
    <div className="xref">
      <div className="panel-head">
        <span>{dir === "paths" ? "reachability" : "xrefs"}</span>
        <span className="count">({dir === "paths" ? paths.length : rows.length})</span>
        <div className="spacer" />
        <div className="seg">
          <button className={dir === "to" ? "active" : ""} onClick={() => onDir("to")}>
            callers
          </button>
          <button className={dir === "from" ? "active" : ""} onClick={() => onDir("from")}>
            callees
          </button>
          <button
            className={dir === "paths" ? "active" : ""}
            title="how control reaches this function from an entry point or export"
            onClick={() => onDir("paths")}
          >
            paths
          </button>
        </div>
      </div>
      <div className="rows">
        {dir === "paths" ? (
          paths.length === 0 ? (
            <div className="xref-row" style={{ color: "var(--faint)" }}>
              nothing reaches this from an entry point or export
            </div>
          ) : (
            paths.map((p, i) => (
              <div key={i} className="pathrow">
                {p.hops.map((h, j) => (
                  <span key={j}>
                    {j > 0 && <span className="phop">{"›"}</span>}
                    <span className="pname" onClick={() => onJump(h.addr)} title={h.addr}>
                      {h.name}
                    </span>
                  </span>
                ))}
              </div>
            ))
          )
        ) : (
          <>
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
          </>
        )}
      </div>
    </div>
  );
}
