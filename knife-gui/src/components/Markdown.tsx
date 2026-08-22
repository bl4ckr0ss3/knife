import type { ReactNode } from "react";

/**
 * A small markdown renderer, dependency-free.
 *
 * The model answers in markdown — headings, tables, fenced code — and rendering
 * it as raw text throws that away: the IOCTL table it produced showed as
 * pipe-delimited lines. This handles the subset the model actually uses
 * (headings, bold, inline and fenced code, and GitHub pipe tables) and nothing
 * more, because a full markdown engine is a dependency and an attack surface we
 * do not need for our own model's output.
 *
 * Addresses stay live: `0x…` runs inside any text become clickable and jump
 * through `onJump`, so an answer is a way into the code, not just prose about it.
 */

function linkify(text: string, onJump: (a: string) => void): ReactNode[] {
  return text.split(/(0x[0-9a-fA-F]{4,})/g).map((part, i) =>
    /^0x[0-9a-fA-F]{4,}$/.test(part) ? (
      <span key={i} className="caddr" onClick={() => onJump(part)}>
        {part}
      </span>
    ) : (
      <span key={i}>{part}</span>
    ),
  );
}

/** Inline spans: **bold** and `code`, with addresses linked inside plain runs. */
function inline(text: string, onJump: (a: string) => void): ReactNode[] {
  const out: ReactNode[] = [];
  // Split on `code` and **bold**, keeping the delimiters.
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  parts.forEach((p, i) => {
    if (p.startsWith("`") && p.endsWith("`")) {
      out.push(
        <code key={i} className="md-code">
          {p.slice(1, -1)}
        </code>,
      );
    } else if (p.startsWith("**") && p.endsWith("**")) {
      out.push(<strong key={i}>{linkify(p.slice(2, -2), onJump)}</strong>);
    } else if (p) {
      out.push(...linkify(p, onJump).map((n, j) => <span key={`${i}-${j}`}>{n}</span>));
    }
  });
  return out;
}

function splitRow(row: string): string[] {
  return row
    .replace(/^\s*\|/, "")
    .replace(/\|\s*$/, "")
    .split("|")
    .map((c) => c.trim());
}

const isTableSep = (row: string) => /^\s*\|?[\s:|-]+\|?\s*$/.test(row) && row.includes("-");

export function Markdown({
  text,
  onJump,
}: {
  text: string;
  onJump: (addr: string) => void;
}) {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block.
    if (line.trimStart().startsWith("```")) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) {
        body.push(lines[i]);
        i++;
      }
      i++; // closing fence
      blocks.push(
        <pre key={key++} className="md-pre">
          {linkify(body.join("\n"), onJump)}
        </pre>,
      );
      continue;
    }

    // Table: a header row, a separator, then body rows.
    if (line.includes("|") && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const header = splitRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) {
        rows.push(splitRow(lines[i]));
        i++;
      }
      blocks.push(
        <table key={key++} className="md-table">
          <thead>
            <tr>
              {header.map((h, j) => (
                <th key={j}>{inline(h, onJump)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, ri) => (
              <tr key={ri}>
                {r.map((c, ci) => (
                  <td key={ci}>{inline(c, onJump)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>,
      );
      continue;
    }

    // Heading.
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      const level = h[1].length;
      blocks.push(
        <div key={key++} className={`md-h md-h${level}`}>
          {inline(h[2], onJump)}
        </div>,
      );
      i++;
      continue;
    }

    // Bullet.
    const b = line.match(/^\s*[-*]\s+(.*)$/);
    if (b) {
      blocks.push(
        <div key={key++} className="md-li">
          <span className="md-bullet">›</span>
          <span>{inline(b[1], onJump)}</span>
        </div>,
      );
      i++;
      continue;
    }

    // Blank line → spacing; anything else → a paragraph line.
    if (line.trim() === "") {
      blocks.push(<div key={key++} className="md-gap" />);
    } else {
      blocks.push(
        <div key={key++} className="md-p">
          {inline(line, onJump)}
        </div>,
      );
    }
    i++;
  }

  return <div className="md">{blocks}</div>;
}
