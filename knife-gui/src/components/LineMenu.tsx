import { useEffect, useRef } from "react";
import type { LineActions } from "../api";

export interface MenuItem {
  label: string;
  hint?: string;
  disabled?: boolean;
  run: () => void;
}

/**
 * The context menu on a pseudocode line.
 *
 * It offers only what the line actually supports, which is the point: a line
 * with no `->` cannot have a field named, and naming a field is meaningless
 * until a type is bound to the pointer it hangs off. Showing the impossible
 * options greyed out teaches the order they go in.
 */
export function LineMenu({
  at,
  items,
  onClose,
}: {
  at: { x: number; y: number };
  items: MenuItem[];
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const away = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) onClose();
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("mousedown", away);
    window.addEventListener("keydown", esc);
    return () => {
      window.removeEventListener("mousedown", away);
      window.removeEventListener("keydown", esc);
    };
  }, [onClose]);

  // Keep the menu inside the window when the click was near an edge.
  const style: React.CSSProperties = {
    left: Math.min(at.x, window.innerWidth - 260),
    top: Math.min(at.y, window.innerHeight - items.length * 26 - 16),
  };

  return (
    <div className="linemenu" style={style} ref={ref}>
      {items.map((it, i) => (
        <div
          key={i}
          className={"lmitem" + (it.disabled ? " disabled" : "")}
          onClick={() => {
            if (it.disabled) return;
            it.run();
            onClose();
          }}
        >
          <span className="lmlabel">{it.label}</span>
          {it.hint && <span className="lmhint">{it.hint}</span>}
        </div>
      ))}
    </div>
  );
}

/** Build the menu for a pseudocode line from what the backend found in it. */
export function pseudoMenu(
  actions: LineActions | undefined,
  handlers: {
    bindType: (base: string) => void;
    nameField: (typeName: string, offset: number, member: string) => void;
    renameVar: (base: string) => void;
    setPrototype: () => void;
  },
): MenuItem[] {
  const items: MenuItem[] = [];
  const field = actions?.field ?? null;
  const variable = actions?.variable ?? null;

  if (field) {
    items.push({
      label: `Bind type to ${field.base}`,
      hint: field.type_name ? field.type_name : "t",
      run: () => handlers.bindType(field.base),
    });
    const sign = field.offset < 0 ? "-" : "+";
    const mag = Math.abs(field.offset).toString(16);
    items.push({
      label: `Name field ${sign}0x${mag}`,
      hint: field.type_name ? "e" : "bind a type first",
      disabled: !field.type_name,
      run: () =>
        field.type_name && handlers.nameField(field.type_name, field.offset, field.member),
    });
  }
  if (variable) {
    items.push({
      label: `Rename ${variable}`,
      hint: "l",
      run: () => handlers.renameVar(variable),
    });
  }
  items.push({ label: "Set prototype", hint: "p", run: handlers.setPrototype });
  return items;
}
