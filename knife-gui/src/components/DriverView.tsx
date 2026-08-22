import type { DriverReport } from "../api";

/**
 * What a kernel driver exposes, and what it lets you reach.
 *
 * The order is the order the question is asked in: which devices user mode can
 * open, which dispatch handlers those reach, which IOCTL codes they accept, and
 * finally which kernel primitives sit behind them. A primitive nothing can
 * reach is context; one reachable from a dispatch handler is the finding.
 */
export function DriverView({
  report,
  reachableOnly,
  criticalOnly,
  onToggleReachable,
  onToggleCritical,
  onJump,
}: {
  report: DriverReport | null;
  reachableOnly: boolean;
  criticalOnly: boolean;
  onToggleReachable: () => void;
  onToggleCritical: () => void;
  onJump: (addr: string) => void;
}) {
  if (!report) {
    return (
      <div className="list">
        <div className="empty-hint">
          not a driver
          <br />
          <span>no kernel surface was found in this image</span>
        </div>
      </div>
    );
  }

  return (
    <div className="list">
      {report.known_bad.length > 0 && (
        <>
          <div className="sym-module bad">KNOWN VULNERABLE ({report.known_bad.length})</div>
          {report.known_bad.map((k, i) => (
            <div key={i} className="drow">
              <span className="dname bad">{k.product || k.file}</span>
              <span className="ddetail">
                {[k.vendor, k.category].filter(Boolean).join(" ")}
                {k.malicious ? " malicious" : ""}
              </span>
            </div>
          ))}
        </>
      )}

      <div className="sym-module">IDENTITY</div>
      <div className="drow" onClick={() => onJump(report.entry)}>
        <span className="dname">{report.entry_name || "entry"}</span>
        <span className="ddetail">{report.entry.replace("0x", "")}</span>
      </div>
      {report.why.slice(0, 3).map((w, i) => (
        <div key={i} className="drow">
          <span className="ddetail wide">{w}</span>
        </div>
      ))}

      <div className="sym-module">DEVICES ({report.devices.length})</div>
      {report.devices.length === 0 && <div className="drow"><span className="ddetail">none found</span></div>}
      {report.devices.map((d, i) => (
        <div key={i} className="drow" onClick={() => onJump(d.addr)}>
          <span className={"dname" + (d.created ? " created" : "")}>{d.name}</span>
          <span className="ddetail">
            {d.created ? "created " : ""}
            {d.xrefs} refs
          </span>
        </div>
      ))}

      <div className="sym-module">IRP DISPATCH ({report.irp.length})</div>
      {report.irp.map((h, i) => (
        <div key={i} className="drow" onClick={() => onJump(h.addr)}>
          <span className="dname">{h.derived || h.name}</span>
          <span className="ddetail">
            {h.major} {h.addr.replace("0x", "")}
          </span>
        </div>
      ))}

      <div className="sym-module">IOCTLS ({report.ioctls.length})</div>
      {report.ioctls.map((c, i) => (
        <div key={i} className="drow" onClick={() => onJump(c.addr)}>
          <span className="dname">{c.code}</span>
          <span className="ddetail">
            {c.method} fn {c.function}
          </span>
        </div>
      ))}

      <div className="sym-module">
        PRIMITIVES ({report.primitives.length})
        <span className="dfilters">
          <span
            className={"dfilter" + (reachableOnly ? " on" : "")}
            title="only primitives user mode can reach"
            onClick={(e) => {
              e.stopPropagation();
              onToggleReachable();
            }}
          >
            reachable
          </span>
          <span
            className={"dfilter" + (criticalOnly ? " on" : "")}
            title="only critical primitives"
            onClick={(e) => {
              e.stopPropagation();
              onToggleCritical();
            }}
          >
            critical
          </span>
        </span>
      </div>
      {report.primitives.length === 0 && (
        <div className="drow">
          <span className="ddetail">nothing matches the current filters</span>
        </div>
      )}
      {report.primitives.map((p, i) => (
        <div
          key={i}
          className="drow"
          onClick={() => p.sites[0] && onJump(p.sites[0].from)}
          title={p.sites.map((s) => `${s.in_func ?? "?"}+${s.at_off}`).join("\n")}
        >
          <span className={"sev s" + Math.min(p.severity, 3)}>
            {p.severity >= 3 ? "[H]" : p.severity >= 2 ? "[M]" : "[L]"}
          </span>
          <span className={"dname" + (p.reachable ? "" : " unreachable")}>{p.api}</span>
          <span className="ddetail">
            {p.class} {p.sites.length} site{p.sites.length === 1 ? "" : "s"}
            {p.reachable ? " reachable" : ""}
          </span>
        </div>
      ))}
    </div>
  );
}
