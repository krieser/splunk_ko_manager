/**
 * SVG die faces approximating SF Symbols die.face.{1-6}.fill
 */

const DOT_POSITIONS = {
  1: [[0.5, 0.5]],
  2: [
    [0.28, 0.28],
    [0.72, 0.72],
  ],
  3: [
    [0.28, 0.28],
    [0.5, 0.5],
    [0.72, 0.72],
  ],
  4: [
    [0.28, 0.28],
    [0.72, 0.28],
    [0.28, 0.72],
    [0.72, 0.72],
  ],
  5: [
    [0.28, 0.28],
    [0.72, 0.28],
    [0.5, 0.5],
    [0.28, 0.72],
    [0.72, 0.72],
  ],
  6: [
    [0.28, 0.25],
    [0.72, 0.25],
    [0.28, 0.5],
    [0.72, 0.5],
    [0.28, 0.75],
    [0.72, 0.75],
  ],
};

/**
 * @param {number} value 1–6
 * @returns {string} SVG markup
 */
export function renderDieFace(value) {
  const clamped = Math.max(1, Math.min(6, value));
  const dots = DOT_POSITIONS[clamped]
    .map(
      ([x, y]) =>
        `<circle cx="${x * 100}" cy="${y * 100}" r="9" fill="currentColor"/>`
    )
    .join("");

  return `
    <svg class="die" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-label="Die showing ${clamped}">
      <rect x="4" y="4" width="92" height="92" rx="16" ry="16" fill="currentColor" opacity="0.15"/>
      <rect x="4" y="4" width="92" height="92" rx="16" ry="16" fill="none" stroke="currentColor" stroke-width="3"/>
      ${dots}
    </svg>
  `.trim();
}
