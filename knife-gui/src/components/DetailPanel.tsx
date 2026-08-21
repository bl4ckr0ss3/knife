import type { ReactNode } from "react";
import type { BinaryDetail } from "../api";
import { Section } from "./Section";

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
      <Section title="Binary" storageKey="binary">
        <KV k="format" v={`${d.format} · ${d.arch} · ${d.bits}-bit`} />
        <KV k="size" v={human(d.size)} />
        <KV k="kind" v={[d.is_lib ? "library" : "executable", d.is_stripped ? "stripped" : "symbols"].join(" · ")} />
        <KV k="image base" v={d.image_base} />
        <KV k="entry" v={d.entry} />
        {d.subsystem && <KV k="subsystem" v={d.subsystem} />}
        <KV k="functions" v={`${d.functions} (${d.named} named)`} />
      </Section>

      <Section title="Triage" storageKey="triage">
        <div className="kv">
          <span className="k">verdict</span>
          <span className={"v verdict " + d.triage.verdict}>
            {d.triage.verdict} · score {d.triage.score}
          </span>
        </div>
        {d.triage.signals.slice(0, 8).map((s, i) => (
          <div className="mit" key={i}>
            <span className={"st " + s.kind}>•</span>
            <span className="nm">{s.text}</span>
          </div>
        ))}
      </Section>

      <Section
        title="Mitigations"
        storageKey="mitigations"
        right={
          <span className={d.mitigations.missing > 0 ? "sr-bad" : "sr-ok"}>
            {d.mitigations.exposure} · {d.mitigations.missing}/{d.mitigations.applicable} missing
          </span>
        }
      >
        {d.mitigations.findings.map((m, i) => (
          <div className="mit" key={i} title={[m.state, m.detail, m.impact].filter(Boolean).join(" — ")}>
            <span className={"st " + m.kind}>
              {m.kind === "info" ? "[+]" : m.kind === "bad" ? "[-]" : m.kind === "warn" ? "[=]" : "[ ]"}
            </span>
            <span className={"nm" + (m.kind === "bad" ? " bad" : "")}>{m.name}</span>
          </div>
        ))}
      </Section>

      <Section title="Hashes" storageKey="hashes" defaultOpen={false}>
        <KV k="sha256" v={d.hashes.sha256} />
        <KV k="sha1" v={d.hashes.sha1} />
        <KV k="md5" v={d.hashes.md5} />
        {d.hashes.imphash && <KV k="imphash" v={d.hashes.imphash} />}
      </Section>

      <Section title="Signing" storageKey="signing">
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
      </Section>

      <Section
        title="Sections"
        storageKey="sections"
        defaultOpen={false}
        right={<span className="sr-dim">{d.sections.length}</span>}
      >
        {d.sections.map((s, i) => (
          <div className="kv" key={i}>
            <span className="k">{s.name || "(unnamed)"}</span>
            <span className="v">
              {s.flags} · {human(s.vsize)} · H {s.entropy.toFixed(2)}
            </span>
          </div>
        ))}
      </Section>
    </div>
  );
}
