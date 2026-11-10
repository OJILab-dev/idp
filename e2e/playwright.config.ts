// The e2e suite (docs/design/technology.md, "e2e テスト"): black-box browser tests against the IdP Worker running on
// workerd, with Chromium's virtual authenticator standing in for the user's passkey provider.
import { defineConfig, devices } from "@playwright/test";
import { HOSTING } from "./support/hosting.js";

export default defineConfig({
  testDir: "./tests",
  // One directory per hosting mode, so a failure's trace names the run it came from.
  outputDir: `./dist/test-results/${HOSTING.mode}`,
  globalSetup: "./global-setup.ts",
  // Each worker process starts its own workerd; one keeps a loaded machine (and the CI runner) from timing out.
  workers: 1,
  fullyParallel: false,
  forbidOnly: process.env["CI"] !== undefined,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    locale: "en-US",
    trace: "retain-on-failure",
  },
});
