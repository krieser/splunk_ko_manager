#!/usr/bin/env node
/** Headless runner for simulator/tests.js (same suite as the browser button). */

import { runBrowserTests } from "../simulator/tests.js";

const { passed, failed, lines } = runBrowserTests();

for (const line of lines) {
  console.log(line);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
