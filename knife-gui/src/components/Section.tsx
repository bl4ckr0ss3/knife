import { useState, type ReactNode } from "react";

/**
 * A collapsible block in the detail panel.
 *
 * The panel is taller than the window on any real binary — a section table
 * alone can run past the bottom edge — so each group folds, and whether it is
 * folded is remembered. Storage failures are ignored: a private window losing a
 * fold state is not worth an error.
 */
export function Section({
  title,
  right,
  defaultOpen = true,
  storageKey,
  children,
}: {
  title: string;
  right?: ReactNode;
  defaultOpen?: boolean;
  storageKey: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(() => {
    try {
      const raw = window.localStorage.getItem("knife.sec." + storageKey);
      return raw === null ? defaultOpen : raw === "1";
    } catch {
      return defaultOpen;
    }
  });

  const toggle = () => {
    setOpen((o) => {
      try {
        window.localStorage.setItem("knife.sec." + storageKey, o ? "0" : "1");
      } catch {
        // Not worth failing over.
      }
      return !o;
    });
  };

  return (
    <div className="detail-sec">
      <h4 onClick={toggle} className={open ? "" : "closed"}>
        <span className="caret">{open ? "▾" : "▸"}</span>
        <span className="stitle">{title}</span>
        {right && <span className="sright">{right}</span>}
      </h4>
      {open && <div className="sbody">{children}</div>}
    </div>
  );
}
