import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Property tests hash a few hundred thousand nodes; give them room on slow CI.
    testTimeout: 60_000,
  },
});
