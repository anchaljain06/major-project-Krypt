import { defineConfig, devices } from "@playwright/test";

// End-to-end tests against a running backend + Vite dev server.
// See e2e/README.md for how to start them.
export default defineConfig({
  testDir: "./e2e",
  // The attack specs need a relay in EVIL_MODE; the runners in evaluation/attacks set ATTACK.
  // The benchmarks run only from evaluation/files-bench, which sets BENCH.
  testIgnore: [...(process.env.ATTACK ? [] : [/attacks.*\.spec\.ts$/]), ...(process.env.BENCH ? [] : [/bench.*\.spec\.ts$/])],
  timeout: 300_000,
  expect: { timeout: 30_000 },
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:5199",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
