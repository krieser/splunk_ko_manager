# Dice Roll Simulator

A web-based simulator and test suite for the SwiftUI **Dice Roll** app. Because SwiftUI requires macOS/iOS and Xcode, this project provides a faithful browser simulator plus automated logic tests you can run on any platform.

## Project layout

```
dice-simulator/
├── swift/ContentView.swift   # Original SwiftUI source
├── simulator/                # Web simulator (HTML/CSS/JS)
│   ├── index.html
│   ├── app.js
│   ├── dice-logic.js         # JS port of rollDice()
│   ├── dice-faces.js         # SVG die faces (SF Symbols style)
│   ├── tests.js              # In-browser test runner
│   └── styles.css
├── tests/test_dice_logic.py  # Python unit tests
└── serve.py                  # Local dev server
```

## Run the simulator

```bash
cd dice-simulator
python3 serve.py
```

Open **http://localhost:8080/** in your browser. Click **Roll Dice** to spin the dice and update the total. Use **Run Tests** in the test panel to validate the logic in-browser.

## Run automated tests

```bash
python3 dice-simulator/tests/test_dice_logic.py
```

Or with `unittest` discovery:

```bash
python3 -m unittest discover -s dice-simulator/tests -v
```

## SwiftUI (native)

To run the original Swift code, open `swift/ContentView.swift` in an Xcode iOS/macOS SwiftUI project and use the Simulator or a device. The web simulator mirrors:

| SwiftUI | Web simulator |
|---------|---------------|
| `@State die1, die2, score, isRolling` | `createInitialState()` / `rollDice()` |
| `Int.random(in: 1...6)` | `Math.floor(Math.random() * 6) + 1` |
| `.rotationEffect(.degrees(isRolling ? 360 : 0))` | CSS spring rotation on `.dice-row` |
| `die.face.{n}.fill` SF Symbols | SVG die faces in `dice-faces.js` |

## What the tests cover

- Initial state (`die1=1`, `die2=1`, `score=2`, `isRolling=false`)
- `isRolling` toggles on each roll
- Score always equals `die1 + die2`
- Die values stay in range 1–6
- Deterministic RNG for reproducible assertions
- Rough uniformity of random rolls (Python suite)
