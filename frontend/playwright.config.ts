import { defineConfig, devices } from "@playwright/test";

// End-to-end tests against a running backend + Vite dev server.
// See e2e/README.md for how to start them.
export default defineConfig({
  testDir: "./e2e",
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
