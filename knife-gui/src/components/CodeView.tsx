import type { Finding, IrLine, Line } from "../api";

// The centre pane: disassembly or decompiled pseudocode. A single click selects
// a line (so a note, or a type binding, can be attached to it); clicking an
// underlined operand, or double-clicking, follows the call or branch.
export function CodeView({
  tab,
  lines,
  ir,
  selected,
  irSelected,
  hits,
  currentHit,
  findingAt,
  primAt,
  onSelect,
  onSelectIr,
  onFollow,
  onLineMenu,
  onFinding,
  onPrimitive,
}: {
  tab: "disasm" | "pseudo";
  lines: Line[];
  ir: IrLine[];
  selected: string | null;
  irSelected: number | null;
  /// Line indices matching the find query, and which one is current.
  hits: number[];
  currentHit: number | null;
  /// Instruction address -> the audit finding at that call site, so a dangerous
  /// call is visible while reading, not only in the attack-surface list.
  findingAt: Map<string, Finding>;
  /// Instruction address -> kernel primitive at that call site (driver targets).
  /// A finding takes precedence, so this only marks primitives the audit did not
  /// already flag: MmMapIoSpace, __readmsr, token swaps and friends.
  primAt: Map<string, { api: string; severity: number }>;
  onSelect: (addr: string) => void;
  onSelectIr: (index: number) => void;
  onFollow: (selector: string) => void;
  onLineMenu: (index: number, at: { x: number; y: number }) => void;
  onFinding: (f: Finding) => void;
  onPrimitive: () => void;
}) {
  // A set, not a scan: a large function is thousands of lines and this runs for
  // every one of them on every render.
  const hitSet = new Set(hits);
  const hitClass = (i: number) =>
    hitSet.has(i) ? (currentHit === i ? " hit cur" : " hit") : "";

  if (tab === "pseudo") {
    // Right-click is where the workbench lives: bind a type, name a field,
    // rename a variable, set the prototype. Selecting the line first is what
    // lets the keyboard equivalents (t / e / l / p) know what they act on.
    return (
      <div className="code">
        {ir.map((l, i) => (
          <div
            key={i}
            data-line={i}
            className={
              "ir" + (l.label ? " label" : "") + (irSelected === i ? " sel" : "") + hitClass(i)
            }
            onClick={() => onSelectIr(i)}
            onContextMenu={(e) => {
              e.preventDefault();
              onSelectIr(i);
              onLineMenu(i, { x: e.clientX, y: e.clientY });
            }}
          >
            {l.text || " "}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="code">
      {lines.map((l, i) => {
        if (l.kind === "label") {
          return (
            <div key={i} data-line={i} className={"ln" + hitClass(i)}>
              <span className="gutter" />
              <span className="label">{l.text}</span>
            </div>
          );
        }
        if (l.kind === "data") {
          return (
            <div key={i} data-line={i} className={"ln" + hitClass(i)}>
              <span className="gutter">{l.addr.replace("0x", "")}</span>
              <span className="ops">{l.text}</span>
            </div>
          );
        }
        const finding = findingAt.get(l.addr);
        const prim = finding ? undefined : primAt.get(l.addr);
        return (
          <div
            key={i}
            data-line={i}
            className={
              "ln selectable" +
              (l.addr === selected ? " sel" : "") +
              hitClass(i) +
              (finding ? " danger s" + Math.min(finding.severity, 3) : "") +
              (prim ? " kprim" : "")
            }
            onClick={() => onSelect(l.addr)}
            onDoubleClick={() => l.target && onFollow(l.target)}
          >
            <span className="gutter">{l.addr.replace("0x", "")}</span>
            <span className="mnem">{l.mnemonic}</span>
            {l.target ? (
              <span className="ops">
                <span
                  className="target"
                  onClick={(e) => {
                    e.stopPropagation();
                    onFollow(l.target!);
                  }}
                >
                  {l.operands}
                </span>
              </span>
            ) : (
              <span className="ops">{l.operands}</span>
            )}
            {l.annot && <span className={"annot " + l.annot.kind}>; {l.annot.text}</span>}
            {finding && (
              <span
                className="danger-flag"
                title={`${finding.pattern}: ${finding.detail}`}
                onClick={(e) => {
                  e.stopPropagation();
                  onFinding(finding);
                }}
              >
                {finding.severity >= 3 ? "⚑ high" : finding.severity >= 2 ? "⚑ med" : "⚑"}
              </span>
            )}
            {prim && (
              <span
                className="kprim-flag"
                title={`kernel primitive: ${prim.api}`}
                onClick={(e) => {
                  e.stopPropagation();
                  onPrimitive();
                }}
              >
                ⎈ {prim.api}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
