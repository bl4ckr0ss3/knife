import type { Finding } from "../api";

const sevLabel = (s: number) => (s >= 3 ? "H" : s >= 2 ? "M" : "L");

export function AttackSurface({
  findings,
  selected,
  onPick,
}: {
  findings: Finding[];
  selected: string | null;
  onPick: (f: Finding) => void;
}) {
  return (
    <div className="list">
      {findings.length === 0 && (
        <div className="finding" style={{ color: "var(--faint)" }}>
          no findings
        </div>
      )}
      {findings.map((f, i) => (
        <div
          key={i}
          className={"finding" + (f.addr === selected ? " sel" : "")}
          onClick={() => onPick(f)}
        >
          <div className="top">
            <span className={"sev s" + f.severity}>[{sevLabel(f.severity)}]</span>
            <span className="pat">{f.pattern.replace(/-/g, " ")}</span>
            <span className="where">{f.func ?? f.addr.replace("0x", "")}</span>
          </div>
          <div className="detail">
            {f.api} @ {f.addr.replace("0x", "")}
            {f.reachable ? " · reachable" : ""}
          </div>
        </div>
      ))}
    </div>
  );
}
