import type { IrLine, Line } from "../api";

// The centre pane: disassembly or decompiled pseudocode. A single click selects
// a line (so a note, or a type binding, can be attached to it); clicking an
// underlined operand, or double-clicking, follows the call or branch.
export function CodeView({
  tab,
  lines,
  ir,
  selected,
  irSelected,
  onSelect,
  onSelectIr,
  onFollow,
  onLineMenu,
}: {
  tab: "disasm" | "pseudo";
  lines: Line[];
  ir: IrLine[];
  selected: string | null;
  irSelected: number | null;
  onSelect: (addr: string) => void;
  onSelectIr: (index: number) => void;
  onFollow: (selector: string) => void;
  onLineMenu: (index: number, at: { x: number; y: number }) => void;
}) {
  if (tab === "pseudo") {
    // Right-click is where the workbench lives: bind a type, name a field,
    // rename a variable, set the prototype. Selecting the line first is what
    // lets the keyboard equivalents (t / e / l / p) know what they act on.
    return (
      <div className="code">
        {ir.map((l, i) => (
          <div
            key={i}
            className={"ir" + (l.label ? " label" : "") + (irSelected === i ? " sel" : "")}
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
