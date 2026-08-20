import { createInitialState, rollDice } from "./dice-logic.js";
import { renderDieFace } from "./dice-faces.js";
import { runBrowserTests } from "./tests.js";

const die1El = document.getElementById("die1");
const die2El = document.getElementById("die2");
const scoreEl = document.getElementById("score");
const diceRowEl = document.getElementById("dice-row");
const rollButton = document.getElementById("roll-button");
const testResultsEl = document.getElementById("test-results");
const runTestsButton = document.getElementById("run-tests");

let state = createInitialState();
let animating = false;

function render() {
  die1El.innerHTML = renderDieFace(state.die1);
  die2El.innerHTML = renderDieFace(state.die2);
  scoreEl.textContent = `Total: ${state.score}`;
}

function handleRoll() {
  if (animating) return;

  animating = true;
  rollButton.disabled = true;

  // Match Swift: update state (including isRolling toggle) inside animation
  state = rollDice(state);
  render();

  // Reset then re-apply rotation so each roll spins (spring-like CSS transition)
  diceRowEl.classList.remove("rolling");
  void diceRowEl.offsetWidth;
  if (state.isRolling) {
    diceRowEl.classList.add("rolling");
  }

  setTimeout(() => {
    animating = false;
    rollButton.disabled = false;
  }, 450);
}

rollButton.addEventListener("click", handleRoll);

runTestsButton.addEventListener("click", () => {
  const { passed, failed, lines } = runBrowserTests();
  testResultsEl.innerHTML = lines
    .map((line) => {
      if (line.startsWith("✓")) return `<span class="test-pass">${line}</span>`;
      if (line.startsWith("✗")) return `<span class="test-fail">${line}</span>`;
      return line;
    })
    .join("\n");
  testResultsEl.insertAdjacentHTML(
    "beforeend",
    `\n\n${passed} passed, ${failed} failed`
  );
});

render();
