/**
 * Rail icons.
 *
 * These were text glyphs (`ƒ`, `⚠`, `T`, `{}`, `±`) picked for being one
 * character each, which made the rail read as a row of mismatched typography:
 * different weights, different optical sizes, some of them barely visible.
 * Drawn strokes share a grid, a weight, and a cap style, so the column reads as
 * one set.
 *
 * Everything is `currentColor` on a 24-unit grid with a 1.6 stroke, so the
 * active/hover colours in the stylesheet apply without the icons knowing.
 */

const S = {
  width: 20,
  height: 20,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

/** Functions: a list whose rows are code. */
export const IconFunctions = () => (
  <svg {...S}>
    <path d="M4 6h10M4 12h13M4 18h8" />
    <path d="M19 5.5v4" />
    <path d="M17 7.5h4" />
  </svg>
);

/** Attack surface: a warning triangle. */
export const IconAttack = () => (
  <svg {...S}>
    <path d="M12 4.5 21 19H3z" />
    <path d="M12 10v4" />
    <path d="M12 16.6v.2" />
  </svg>
);

/** Strings: quoted text. */
export const IconStrings = () => (
  <svg {...S}>
    <path d="M8 8.5c-1.6 0-2.6 1-2.6 2.4S6.4 13 7.7 13c1 0 1.6.5 1.6 1.3 0 1-.9 1.7-2.3 1.7" />
    <path d="M17 8.5c-1.6 0-2.6 1-2.6 2.4s1 2.1 2.3 2.1c1 0 1.6.5 1.6 1.3 0 1-.9 1.7-2.3 1.7" />
  </svg>
);

/** Imports: arriving. */
export const IconImports = () => (
  <svg {...S}>
    <path d="M12 3.5v11" />
    <path d="M8 11l4 4 4-4" />
    <path d="M4.5 19.5h15" />
  </svg>
);

/** Exports: leaving. */
export const IconExports = () => (
  <svg {...S}>
    <path d="M12 20.5v-11" />
    <path d="M8 13l4-4 4 4" />
    <path d="M4.5 4.5h15" />
  </svg>
);

/** Driver: a kernel plug. */
export const IconDriver = () => (
  <svg {...S}>
    <rect x="6.5" y="9" width="11" height="9" rx="1.5" />
    <path d="M9.5 9V5.5M14.5 9V5.5" />
    <path d="M10 18v2M14 18v2" />
  </svg>
);

/** Analyst facts: a brace, for types. */
export const IconFacts = () => (
  <svg {...S}>
    <path d="M9.5 4.5C7.5 4.5 8 10 5.5 12c2.5 2 2 7.5 4 7.5" />
    <path d="M14.5 4.5c2 0 1.5 5.5 4 7.5-2.5 2-2 7.5-4 7.5" />
  </svg>
);

/** Patches: bytes swapped in place. */
export const IconPatches = () => (
  <svg {...S}>
    <rect x="3.5" y="5.5" width="7" height="6" rx="1" />
    <rect x="13.5" y="12.5" width="7" height="6" rx="1" />
    <path d="M10.5 8.5h6.5a2 2 0 0 1 2 2v1" />
    <path d="M13.5 15.5H7a2 2 0 0 1-2-2v-1" />
  </svg>
);

/** Console: a prompt. */
export const IconConsole = () => (
  <svg {...S}>
    <path d="M5 7.5 9 12l-4 4.5" />
    <path d="M12 16.5h7" />
  </svg>
);

/** Back. */
export const IconBack = () => (
  <svg {...S}>
    <path d="M14.5 6 8.5 12l6 6" />
  </svg>
);

/** Agent: a conversation about the binary. */
export const IconAgent = () => (
  <svg {...S}>
    <path d="M4.5 6.5a2 2 0 0 1 2-2h11a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H10l-4 3.5V15.5H6.5a2 2 0 0 1-2-2z" />
    <path d="M9 10h.01M12 10h.01M15 10h.01" />
  </svg>
);
