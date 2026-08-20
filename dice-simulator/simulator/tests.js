import { createInitialState, rollDice, validateState, rollDie } from "./dice-logic.js";
import { renderDieFace } from "./dice-faces.js";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

/**
 * Lightweight in-browser test runner mirroring Python test suite.
 * @returns {{ passed: number, failed: number, lines: string[] }}
 */
export function runBrowserTests() {
  const lines = [];
  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      lines.push(`✓ ${name}`);
      passed += 1;
    } catch (err) {
      lines.push(`✗ ${name}: ${err.message}`);
      failed += 1;
    }
  }

  test("initial state matches Swift defaults", () => {
    const s = createInitialState();
    assert(s.die1 === 1, "die1 should be 1");
    assert(s.die2 === 1, "die2 should be 1");
    assert(s.score === 2, "score should be 2");
    assert(s.isRolling === false, "isRolling should be false");
  });

  test("rollDice toggles isRolling", () => {
    const s0 = createInitialState();
    const s1 = rollDice(s0, { random: () => 0 });
    assert(s1.isRolling === true, "first roll should set isRolling true");
    const s2 = rollDice(s1, { random: () => 0 });
    assert(s2.isRolling === false, "second roll should set isRolling false");
  });

  test("rollDice computes score as sum", () => {
    let i = 0;
    const seq = [0, 0.999]; // die1=1, die2=6
    const next = rollDice(createInitialState(), {
      random: () => seq[i++],
    });
    assert(next.die1 === 1, "die1");
    assert(next.die2 === 6, "die2");
    assert(next.score === 7, "score");
  });

  test("validateState accepts valid rolls", () => {
    const errors = validateState({ die1: 3, die2: 4, score: 7, isRolling: true });
    assert(errors.length === 0, errors.join("; "));
  });

  test("validateState rejects invalid die values", () => {
    const errors = validateState({ die1: 0, die2: 7, score: 7, isRolling: false });
    assert(errors.length >= 2, "expected die range errors");
  });

  test("validateState rejects score mismatch", () => {
    const errors = validateState({ die1: 2, die2: 3, score: 10, isRolling: false });
    assert(errors.some((e) => e.includes("score")), "score mismatch");
  });

  test("rollDie returns 1–6 over many samples", () => {
    for (let n = 0; n < 500; n += 1) {
      const v = rollDie();
      assert(v >= 1 && v <= 6, `out of range: ${v}`);
    }
  });

  test("renderDieFace produces SVG for each face", () => {
    for (let v = 1; v <= 6; v += 1) {
      const svg = renderDieFace(v);
      assert(svg.includes("<svg"), "svg root");
      assert(svg.includes(`Die showing ${v}`), "aria label");
    }
  });

  test("deterministic RNG produces expected values", () => {
    // random()=0 -> floor(0*6)+1 = 1; random()=5/6 -> floor(0.833*6)+1 = 6
    const r = rollDice(createInitialState(), {
      random: () => 5 / 6,
    });
    assert(r.die1 === 6 && r.die2 === 6 && r.score === 12, "both sixes");
  });

  return { passed, failed, lines };
}
