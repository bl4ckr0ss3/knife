import { useEffect, useMemo, useRef, useState } from "react";
import type { Cfg, CfgNode } from "../api";

// Card geometry, in graph units. Blocks are laid out top-down in layers, the
// way a control-flow graph is read.
const CARD_W = 300;
const HEAD_H = 20;
const LINE_H = 14;
const PAD_Y = 8;
const GAP_X = 44;
const GAP_Y = 56;
const MAX_LINES = 10;

interface Placed {
  node: CfgNode;
  x: number;
  y: number;
  w: number;
  h: number;
}

function cardHeight(n: CfgNode) {
  return HEAD_H + Math.min(n.insns.length, MAX_LINES) * LINE_H + PAD_Y;
}

/**
 * Place blocks in top-down layers.
 *
 * The layer is the *longest* forward distance from the entry, not the shortest.
 * That distinction matters: with shortest-path layering, a block reachable both
 * directly from the entry and by falling through its sibling lands in the same
 * layer as that sibling, and the edge between them is drawn sideways — through
 * the card, as it turns out. Taking the longest path guarantees every forward
 * edge descends at least one layer, so control genuinely reads downward and no
 * edge has to cross a block to arrive.
 *
 * Back edges are excluded from the walk (a loop would otherwise push its own
 * target down forever) and drawn afterwards as returns. Blocks nothing reaches
 * — exception handlers, code the recovery could not attribute — go in a final
 * layer of their own rather than being dropped.
 */
function layout(cfg: Cfg) {
  const byId = new Map(cfg.nodes.map((n) => [n.id, n]));
  const forward = new Map<string, string[]>();
  const indeg = new Map<string, number>();
  for (const n of cfg.nodes) indeg.set(n.id, 0);
  for (const e of cfg.edges) {
    if (e.back || !byId.has(e.from) || !byId.has(e.to)) continue;
    if (!forward.has(e.from)) forward.set(e.from, []);
    forward.get(e.from)!.push(e.to);
    indeg.set(e.to, (indeg.get(e.to) ?? 0) + 1);
  }

  // Longest-path layering over the acyclic part, by Kahn's topological order.
  const layer = new Map<string, number>();
  const queue: string[] = [];
  for (const n of cfg.nodes) {
    if ((indeg.get(n.id) ?? 0) === 0) {
      layer.set(n.id, 0);
      queue.push(n.id);
    }
  }
  const remaining = new Map(indeg);
  while (queue.length) {
    const id = queue.shift()!;
    const d = layer.get(id) ?? 0;
    for (const next of forward.get(id) ?? []) {
      layer.set(next, Math.max(layer.get(next) ?? 0, d + 1));
      const left = (remaining.get(next) ?? 1) - 1;
      remaining.set(next, left);
      if (left === 0) queue.push(next);
    }
  }
  // Anything the topological pass could not settle (a cycle the back-edge flag
  // did not cover) still needs a home.
  const deepest = Math.max(-1, ...[...layer.values()]);
  for (const n of cfg.nodes) if (!layer.has(n.id)) layer.set(n.id, deepest + 1);

  // Group by layer, ordered by address so the picture is stable across runs.
  const layers = new Map<number, CfgNode[]>();
  for (const n of cfg.nodes) {
    const d = layer.get(n.id)!;
    if (!layers.has(d)) layers.set(d, []);
    layers.get(d)!.push(n);
  }
  for (const row of layers.values()) row.sort((a, b) => (a.addr < b.addr ? -1 : 1));

  const placed = new Map<string, Placed>();
  let y = 0;
  let width = 0;
  for (const d of [...layers.keys()].sort((a, b) => a - b)) {
    const row = layers.get(d)!;
    const rowW = row.length * CARD_W + (row.length - 1) * GAP_X;
    width = Math.max(width, rowW);
    let rowH = 0;
    row.forEach((n, i) => {
      const h = cardHeight(n);
      rowH = Math.max(rowH, h);
      placed.set(n.id, { node: n, x: i * (CARD_W + GAP_X) - rowW / 2, y, w: CARD_W, h });
    });
    y += rowH + GAP_Y;
  }
  return { placed, width: width + 80, height: y };
}

const EDGE_COLOR: Record<string, string> = {
  true: "var(--mint)",
  false: "var(--critical)",
  flow: "var(--faint)",
};

export function GraphView({
  cfg,
  onOpenBlock,
}: {
  cfg: Cfg | null;
  onOpenBlock: (addr: string) => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const [sel, setSel] = useState<string | null>(null);

  const model = useMemo(() => (cfg ? layout(cfg) : null), [cfg]);

  // Frame the graph whenever a new function is shown.
  const fit = useMemo(
    () => () => {
      if (!model || !wrap.current) return;
      const box = wrap.current.getBoundingClientRect();
      const k = Math.min(1, Math.min(box.width / model.width, box.height / (model.height + 40)) * 0.92);
      setView({ x: box.width / 2, y: 24, k: Math.max(0.12, k) });
    },
    [model],
  );
  useEffect(() => {
    fit();
  }, [fit]);

  if (!cfg || !model) {
    return <div className="graph-empty">no function open</div>;
  }

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const box = wrap.current!.getBoundingClientRect();
    const mx = e.clientX - box.left;
    const my = e.clientY - box.top;
    setView((v) => {
      const k = Math.min(3, Math.max(0.08, v.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
      // Keep the point under the cursor fixed while zooming.
      return { k, x: mx - ((mx - v.x) * k) / v.k, y: my - ((my - v.y) * k) / v.k };
    });
  };

  return (
    <div className="graph-wrap" ref={wrap} onWheel={onWheel}>
      <div className="graph-tools">
        <button onClick={() => setView((v) => ({ ...v, k: Math.min(3, v.k * 1.2) }))} title="Zoom in">
          +
        </button>
        <button onClick={() => setView((v) => ({ ...v, k: Math.max(0.08, v.k / 1.2) }))} title="Zoom out">
          −
        </button>
        <button onClick={fit} title="Fit">
          ⤢
        </button>
        <span className="zoom">{Math.round(view.k * 100)}%</span>
      </div>

      <svg
        className="graph"
        onMouseDown={(e) => {
          drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
        }}
        onMouseMove={(e) => {
          if (!drag.current) return;
          const d = drag.current;
          setView((v) => ({ ...v, x: d.vx + (e.clientX - d.x), y: d.vy + (e.clientY - d.y) }));
        }}
        onMouseUp={() => (drag.current = null)}
        onMouseLeave={() => (drag.current = null)}
      >
        <defs>
          {["true", "false", "flow", "back"].map((k) => (
            <marker
              key={k}
              id={`arrow-${k}`}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill={k === "back" ? "var(--amber)" : EDGE_COLOR[k]} />
            </marker>
          ))}
        </defs>

        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {cfg.edges.map((e, i) => {
            const a = model.placed.get(e.from);
            const b = model.placed.get(e.to);
            if (!a || !b) return null;
            const color = e.back ? "var(--amber)" : EDGE_COLOR[e.kind] ?? "var(--faint)";
            const x1 = a.x + a.w / 2;
            const y1 = a.y + a.h;
            const x2 = b.x + b.w / 2;
            const y2 = b.y;
            // A back edge loops out to the side so it never hides under the
            // forward path it returns along. A forward edge that skips layers
            // bows outward by the same logic — otherwise it would cross every
            // card in between.
            const skips = Math.abs(b.y - (a.y + a.h)) > GAP_Y * 1.5;
            const bow = skips ? (x2 >= x1 ? 1 : -1) * (CARD_W / 2 + GAP_X) : 0;
            const d = e.back
              ? `M ${x1} ${y1} C ${x1 + 220} ${y1 + 30}, ${x2 + 220} ${y2 - 30}, ${x2} ${y2}`
              : `M ${x1} ${y1} C ${x1 + bow} ${y1 + GAP_Y / 2}, ${x2 + bow} ${y2 - GAP_Y / 2}, ${x2} ${y2}`;
            return (
              <path
                key={i}
                d={d}
                className="edge"
                stroke={color}
                strokeDasharray={e.back ? "5 4" : undefined}
                markerEnd={`url(#arrow-${e.back ? "back" : e.kind})`}
              />
            );
          })}

          {[...model.placed.values()].map((p) => (
            <g
              key={p.node.id}
              transform={`translate(${p.x},${p.y})`}
              className={
                "block" + (p.node.kind === "entry" ? " entry" : "") + (sel === p.node.id ? " sel" : "")
              }
              onClick={() => setSel(p.node.id)}
              onDoubleClick={() => onOpenBlock(p.node.addr)}
            >
              <rect width={p.w} height={p.h} rx="7" />
              <text className="bhead" x="10" y="14">
                {p.node.kind === "entry" ? "entry · " : ""}
                {p.node.addr.replace("0x", "")}
              </text>
              <text className="bmeta" x={p.w - 10} y="14" textAnchor="end">
                {p.node.count}i · {p.node.bytes}b
              </text>
              {p.node.insns.slice(0, MAX_LINES).map((t, i) => (
                <text key={i} className="bline" x="10" y={HEAD_H + 11 + i * LINE_H}>
                  {t.length > 40 ? t.slice(0, 39) + "…" : t}
                </text>
              ))}
              {p.node.insns.length > MAX_LINES && (
                <text className="bmore" x="10" y={HEAD_H + 11 + MAX_LINES * LINE_H}>
                  +{p.node.insns.length - MAX_LINES} more
                </text>
              )}
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}
