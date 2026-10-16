import { defineConfig } from "vitest/config";

// Two projects so the slow known-answer tests can run separately:
//   npm test          -> unit, protocol and property tests
//   npm run test:kat  -> NIST ACVP + Wycheproof vectors through our wrappers
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "unit",
          environment: "node",
          include: ["test/**/*.test.ts"],
          exclude: ["test/kat/**"],
          testTimeout: 120_000,
        },
      },
      {
        test: {
          name: "kat",
          environment: "node",
          include: ["test/kat/**/*.test.ts"],
          testTimeout: 600_000,
        },
      },
    ],
  },
});
