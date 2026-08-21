import type { IrLine, Line } from "../api";

// The centre pane: disassembly or decompiled pseudocode. A single click selects
// an instruction (so a note can be attached to it); clicking an underlined
// operand, or double-clicking a line, follows the call/branch.
export function CodeView({
  tab,
  lines,
  ir,
  selected,
  onSelect,
  onFollow,
}: {
  tab: "disasm" | "pseudo";
  lines: Line[];
  ir: IrLine[];
  selected: string | null;
  onSelect: (addr: string) => void;
  onFollow: (selector: string) => void;
}) {
  if (tab === "pseudo") {
    return (
      <div className="code">
        {ir.map((l, i) => (
          <div key={i} className={"ir" + (l.label ? " label" : "")}>
            {l.text || " "}
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
            <div key={i} className="ln">
              <span className="gutter" />
              <span className="label">{l.text}</span>
            </div>
          );
        }
        if (l.kind === "data") {
          return (
            <div key={i} className="ln">
              <span className="gutter">{l.addr.replace("0x", "")}</span>
              <span className="ops">{l.text}</span>
            </div>
          );
        }
        return (
          <div
            key={i}
            className={"ln selectable" + (l.addr === selected ? " sel" : "")}
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
          </div>
        );
      })}
    </div>
  );
}
