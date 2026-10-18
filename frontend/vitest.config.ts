import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Same alias as vite.config.ts: the KT library is imported from ../shared/src.
const shared = fileURLToPath(new URL("../shared/src/index.ts", import.meta.url));

// Two projects so the slow known-answer tests can run separately:
//   npm test          -> unit, protocol and property tests
//   npm run test:kat  -> NIST ACVP + Wycheproof vectors through our wrappers
export default defineConfig({
  test: {
    projects: [
      {
        resolve: { alias: { "@krypt/shared": shared } },
        test: {
          name: "unit",
          environment: "node",
          include: ["test/**/*.test.ts"],
          exclude: ["test/kat/**"],
          testTimeout: 120_000,
        },
      },
      {
        resolve: { alias: { "@krypt/shared": shared } },
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
