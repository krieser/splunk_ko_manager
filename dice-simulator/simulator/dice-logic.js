/**
 * JavaScript port of the SwiftUI ContentView dice logic.
 * Kept in sync with swift/ContentView.swift for simulator testing.
 */

/**
 * @typedef {{ die1: number, die2: number, score: number, isRolling: boolean }} DiceState
 */

/** @returns {number} Random integer from 1 to 6 (inclusive). */
export function rollDie() {
  return Math.floor(Math.random() * 6) + 1;
}

/**
 * Mirrors Swift's rollDice() state update.
 * @param {DiceState} state
 * @param {{ random?: () => number }} [options] injectable RNG for tests
 * @returns {DiceState}
 */
export function rollDice(state, options = {}) {
  const random = options.random ?? Math.random;

  const nextDie1 = Math.floor(random() * 6) + 1;
  const nextDie2 = Math.floor(random() * 6) + 1;

  return {
    die1: nextDie1,
    die2: nextDie2,
    score: nextDie1 + nextDie2,
    isRolling: !state.isRolling,
  };
}

/** @returns {DiceState} Initial state matching Swift defaults. */
export function createInitialState() {
  return {
    die1: 1,
    die2: 1,
    score: 2,
    isRolling: false,
  };
}

/**
 * Validates dice state invariants from the Swift model.
 * @param {DiceState} state
 * @returns {string[]} list of validation errors (empty if valid)
 */
export function validateState(state) {
  const errors = [];

  if (!Number.isInteger(state.die1) || state.die1 < 1 || state.die1 > 6) {
    errors.push(`die1 must be 1–6, got ${state.die1}`);
  }
  if (!Number.isInteger(state.die2) || state.die2 < 1 || state.die2 > 6) {
    errors.push(`die2 must be 1–6, got ${state.die2}`);
  }
  if (state.score !== state.die1 + state.die2) {
    errors.push(`score must equal die1 + die2 (${state.die1 + state.die2}), got ${state.score}`);
  }
  if (typeof state.isRolling !== "boolean") {
    errors.push("isRolling must be a boolean");
  }

  return errors;
}
