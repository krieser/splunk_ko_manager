# Run on iPhone

The simulator was built in a **remote cloud environment**. `http://localhost:8080` on your iPhone points at the phone itself, not that remote machine — so that URL will always fail on your device.

You have two good options:

---

## Option 1 — Native SwiftUI app (recommended)

Your original code is SwiftUI and runs natively on iPhone. This is the best experience (SF Symbols dice, spring animation, home-screen app).

### Steps (requires a Mac with Xcode)

1. Open **Xcode** → **File → New → Project**
2. Choose **iOS → App**, name it `DiceRoll`, Interface **SwiftUI**
3. Replace the generated files with:
   - `swift/DiceRollApp.swift` → app entry point
   - `swift/ContentView.swift` → your dice UI
4. Plug in your iPhone (or use the iOS Simulator)
5. Select your device at the top of Xcode and press **Run** (▶)

The app installs on your iPhone like any other app.

---

## Option 2 — Web version in Safari (no Mac server)

Use the single-file build that works offline in Safari:

### A. AirDrop or Files

1. Get `standalone.html` onto your iPhone (AirDrop from Mac, email attachment, iCloud Drive, etc.)
2. Open it in **Files** → tap the file → **Share** → **Safari** (or tap to open in Safari)
3. Tap **Roll Dice**

### B. Same Wi‑Fi as a Mac (local server)

On your Mac, in the repo folder:

```bash
cd dice-simulator
python3 serve.py --port 8080
```

Find your Mac’s IP (**System Settings → Network**, e.g. `192.168.1.42`).

On iPhone Safari, open:

```text
http://192.168.1.42:8080/standalone.html
```

Use your Mac’s IP, not `localhost`.

### C. Add to Home Screen (web app)

After opening `standalone.html` in Safari:

1. Tap **Share** (square with arrow)
2. **Add to Home Screen**
3. Launch like a normal app

---

## Why localhost failed

| Where you open the URL | What `localhost` means |
|------------------------|-------------------------|
| Cloud agent / Cursor VM | The remote dev machine (server runs there) |
| Your iPhone | The iPhone itself (no server listening) |

To use the web UI on iPhone, either run the server on a machine your phone can reach (same Wi‑Fi + LAN IP) or open `standalone.html` directly in Safari.

---

## Quick comparison

| Method | Needs Mac? | Best for |
|--------|------------|----------|
| SwiftUI in Xcode | Yes | Real iOS app, SF Symbols, App Store path |
| `standalone.html` in Safari | No | Quick test without Xcode |
| Mac + Wi‑Fi server | Yes (Mac on same network) | Full simulator + tests in browser |
