import type { PatchRun } from "../api";

/**
 * Staged byte edits.
 *
 * knife never writes the file you opened. A patch is a fact in the database —
 * the offset, the bytes expected there, and the bytes to put in their place —
 * applied to a copy when the workspace loads. So this list is the edit, and
 * exporting is the only thing that produces a modified binary.
 */
export function PatchList({
  runs,
  onJump,
  onClear,
  onExport,
}: {
  runs: PatchRun[];
  onJump: (addr: string) => void;
  onClear: (offset: string) => void;
  onExport: () => void;
}) {
  return (
    <>
      <div className="list">
        {runs.length === 0 ? (
          <div className="empty-hint">
            nothing staged
            <br />
            <span>press P on an instruction to stage bytes</span>
          </div>
        ) : (
          runs.map((r) => (
            <div key={r.offset} className="patch">
              <div className="top">
                <span
                  className="paddr"
                  title="go to this address"
                  onClick={() => r.vaddr && onJump(r.vaddr)}
                >
                  {(r.vaddr ?? r.offset).replace("0x", "")}
                </span>
                <span className="plen">{r.len} bytes</span>
                <span className="pclear" title="unstage" onClick={() => onClear(r.offset)}>
                  ✕
                </span>
              </div>
              <div className="pbytes">
                <span className="was">{r.original}</span>
                <span className="arrow">→</span>
                <span className="now">{r.bytes}</span>
              </div>
            </div>
          ))
        )}
      </div>
      {runs.length > 0 && (
        <div className="filter">
          <button className="btn wide" onClick={onExport}>
            Export patched binary
          </button>
        </div>
      )}
    </>
  );
}
