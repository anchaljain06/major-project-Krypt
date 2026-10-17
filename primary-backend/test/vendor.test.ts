import { existsSync } from "fs";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain .mjs build script without types
import { SHARED_SRC, staleFiles } from "../scripts/vendor-shared.mjs";

// The backend uses a committed copy of shared/src (see scripts/vendor-shared.mjs).
// This fails when someone changes shared/ without refreshing the copy.
describe.skipIf(!existsSync(SHARED_SRC))("vendored krypt-shared", () => {
  it("matches ../shared/src", () => {
    expect(staleFiles()).toEqual([]);
  });
});
