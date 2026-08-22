import type { Finding } from "../api";

/**
 * Why a finding is a finding.
 *
 * A list of dangerous API calls is something grep can produce. What makes this
 * an audit is the argument behind each one: where the value came from, how it
 * reached the call, and whether anything outside the binary can drive it. That
 * reasoning is the product, so it gets shown rather than summarised into a
 * severity colour.
 */
export function Evidence({
  finding,
  onJump,
  onPaths,
}: {
  finding: Finding | null;
  onJump: (addr: string) => void;
  onPaths: () => void;
}) {
  if (!finding) return null;

  const level = finding.severity >= 3 ? "HIGH" : finding.severity >= 2 ? "MEDIUM" : "LOW";
  const tone = finding.severity >= 3 ? "s3" : finding.severity >= 2 ? "s2" : "s1";

  return (
    <div className={"evidence " + tone}>
      <div className="ehead">
        <span className="elevel">{level}</span>
        <span
          className={"ereach " + (finding.reachable ? "yes" : "no")}
          title={
            finding.reachable
              ? "a call site sits in a function reachable from an entry point or export"
              : "no path from an entry point or export was found, which is not proof there is none"
          }
        >
          {finding.reachable ? "REACHABLE" : "UNPROVEN"}
        </span>
        <div className="spacer" />
        <span className="elink" onClick={onPaths}>
          show paths
        </span>
      </div>

      <div className="erow">
        <span className="ekey">pattern</span>
        <span className="epattern">{finding.pattern.replace(/-/g, " ")}</span>
        <span className="ekey">sink</span>
        <span className="esink" onClick={() => onJump(finding.addr)}>
          {finding.api} @ {finding.addr}
        </span>
      </div>

      <div className="erow">
        <span className="ekey">signal</span>
        <span className="echain">
          <b>{finding.source}</b>
          <i>{"→"}</i>DATA FLOW<i>{"→"}</i>
          <b>{finding.api.toUpperCase()}</b>
        </span>
        {finding.func && (
          <>
            <span className="ekey">in</span>
            <span className="efunc">{finding.func}</span>
          </>
        )}
      </div>

      <div className="erow why">
        <span className="ekey">why</span>
        <span className="ewhy">{finding.detail}</span>
      </div>
    </div>
  );
}
