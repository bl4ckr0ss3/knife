import type { ReactNode } from "react";
import type { BinaryDetail } from "../api";

function KV({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className="v">{v}</span>
    </div>
  );
}

const human = (n: number) =>
  n >= 1 << 20
    ? (n / (1 << 20)).toFixed(1) + " MB"
    : n >= 1 << 10
      ? (n / (1 << 10)).toFixed(1) + " KB"
      : n + " B";

export function DetailPanel({ d }: { d: BinaryDetail }) {
  return (
    <div>
      <div className="detail-sec">
        <h4>Binary</h4>
        <KV k="format" v={`${d.format} · ${d.arch} · ${d.bits}-bit`} />
        <KV k="size" v={human(d.size)} />
        <KV k="kind" v={[d.is_lib ? "library" : "executable", d.is_stripped ? "stripped" : "symbols"].join(" · ")} />
        <KV k="image base" v={d.image_base} />
        <KV k="entry" v={d.entry} />
        {d.subsystem && <KV k="subsystem" v={d.subsystem} />}
        <KV k="functions" v={`${d.functions} (${d.named} named)`} />
      </div>

      <div className="detail-sec">
        <h4>Triage</h4>
        <div className="kv">
          <span className="k">verdict</span>
          <span className={"v verdict " + d.triage.verdict}>
            {d.triage.verdict} · score {d.triage.score}
          </span>
        </div>
        {d.triage.signals.slice(0, 8).map((s, i) => (
          <div className="mit" key={i}>
            <span className={"st " + (s.kind === "bad" ? "Off" : s.kind === "warn" ? "Partial" : "On")}>•</span>
            <span className="nm">{s.text}</span>
          </div>
        ))}
      </div>

      <div className="detail-sec">
        <h4>
          Mitigations · {d.mitigations.exposure} ({d.mitigations.missing}/{d.mitigations.applicable} missing)
        </h4>
        {d.mitigations.findings.map((m, i) => (
          <div className="mit" key={i} title={`${m.detail}${m.impact ? "\n" + m.impact : ""}`}>
            <span className={"st " + m.state}>
              {m.state === "On" ? "+" : m.state === "Off" ? "-" : m.state === "Partial" ? "~" : " "}
            </span>
            <span className="nm">{m.name}</span>
          </div>
        ))}
      </div>

      <div className="detail-sec">
        <h4>Hashes</h4>
        <KV k="sha256" v={d.hashes.sha256} />
        <KV k="sha1" v={d.hashes.sha1} />
        <KV k="md5" v={d.hashes.md5} />
        {d.hashes.imphash && <KV k="imphash" v={d.hashes.imphash} />}
      </div>

      <div className="detail-sec">
        <h4>Signing</h4>
        {d.signing.signed ? (
          <>
            <KV k="status" v={`signed · ${d.signing.entries} cert(s)`} />
            {d.signing.subjects.slice(0, 4).map((s, i) => (
              <KV key={i} k={i === 0 ? "subject" : ""} v={s} />
            ))}
          </>
        ) : (
          <KV k="status" v="unsigned" />
        )}
      </div>

      <div className="detail-sec">
        <h4>Sections ({d.sections.length})</h4>
        {d.sections.map((s, i) => (
          <div className="kv" key={i}>
            <span className="k">{s.name || "(unnamed)"}</span>
            <span className="v">
              {s.flags} · {human(s.vsize)} · H {s.entropy.toFixed(2)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
