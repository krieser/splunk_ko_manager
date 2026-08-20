#!/usr/bin/env python3
"""Automated tests for the dice roll logic (Python mirror of dice-logic.js)."""

from __future__ import annotations

import random
import unittest
from dataclasses import dataclass


@dataclass
class DiceState:
    die1: int
    die2: int
    score: int
    is_rolling: bool


def create_initial_state() -> DiceState:
    return DiceState(die1=1, die2=1, score=2, is_rolling=False)


def roll_die(rng: random.Random | None = None) -> int:
    r = rng or random
    return r.randint(1, 6)


def roll_dice(state: DiceState, rng: random.Random | None = None) -> DiceState:
    r = rng or random
    die1 = r.randint(1, 6)
    die2 = r.randint(1, 6)
    return DiceState(
        die1=die1,
        die2=die2,
        score=die1 + die2,
        is_rolling=not state.is_rolling,
    )


def validate_state(state: DiceState) -> list[str]:
    errors: list[str] = []
    if not (1 <= state.die1 <= 6):
        errors.append(f"die1 must be 1–6, got {state.die1}")
    if not (1 <= state.die2 <= 6):
        errors.append(f"die2 must be 1–6, got {state.die2}")
    if state.score != state.die1 + state.die2:
        errors.append(
            f"score must equal die1 + die2 ({state.die1 + state.die2}), got {state.score}"
        )
    if not isinstance(state.is_rolling, bool):
        errors.append("is_rolling must be a boolean")
    return errors


class TestDiceLogic(unittest.TestCase):
    def test_initial_state(self) -> None:
        s = create_initial_state()
        self.assertEqual(s.die1, 1)
        self.assertEqual(s.die2, 1)
        self.assertEqual(s.score, 2)
        self.assertFalse(s.is_rolling)

    def test_roll_toggles_is_rolling(self) -> None:
        s0 = create_initial_state()
        s1 = roll_dice(s0, rng=random.Random(0))
        self.assertTrue(s1.is_rolling)
        s2 = roll_dice(s1, rng=random.Random(0))
        self.assertFalse(s2.is_rolling)

    def test_score_is_sum(self) -> None:
        rng = random.Random(42)
        for _ in range(100):
            s = roll_dice(create_initial_state(), rng=rng)
            self.assertEqual(s.score, s.die1 + s.die2)

    def test_die_values_in_range(self) -> None:
        rng = random.Random(99)
        for _ in range(1000):
            s = roll_dice(create_initial_state(), rng=rng)
            self.assertIn(s.die1, range(1, 7))
            self.assertIn(s.die2, range(1, 7))

    def test_validate_state_valid(self) -> None:
        s = DiceState(die1=3, die2=4, score=7, is_rolling=True)
        self.assertEqual(validate_state(s), [])

    def test_validate_state_invalid_die(self) -> None:
        s = DiceState(die1=0, die2=7, score=7, is_rolling=False)
        errors = validate_state(s)
        self.assertGreaterEqual(len(errors), 2)

    def test_validate_state_score_mismatch(self) -> None:
        s = DiceState(die1=2, die2=3, score=10, is_rolling=False)
        errors = validate_state(s)
        self.assertTrue(any("score" in e for e in errors))

    def test_roll_die_range(self) -> None:
        rng = random.Random(7)
        for _ in range(500):
            v = roll_die(rng)
            self.assertGreaterEqual(v, 1)
            self.assertLessEqual(v, 6)

    def test_distribution_roughly_uniform(self) -> None:
        """Sanity check: each face appears with reasonable frequency."""
        rng = random.Random(12345)
        counts = {i: 0 for i in range(1, 7)}
        trials = 6000
        for _ in range(trials):
            counts[roll_die(rng)] += 1
        expected = trials / 6
        for face, count in counts.items():
            self.assertGreater(
                count,
                expected * 0.7,
                f"face {face} under-represented: {count}",
            )
            self.assertLess(
                count,
                expected * 1.3,
                f"face {face} over-represented: {count}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
