import { describe, expect, it } from "vitest";
import { SlidingWindowLimiter } from "../src/rateLimit.js";

describe("SlidingWindowLimiter", () => {
  it("allows `limit` hits per key per window, then frees them as they age out", () => {
    let t = 0;
    const l = new SlidingWindowLimiter(3, 1000, () => t);
    expect([l.take("a"), l.take("a"), l.take("a"), l.take("a")]).toEqual([true, true, true, false]);
    expect(l.take("b")).toBe(true); // keys are independent
    t = 999;
    expect(l.take("a")).toBe(false);
    t = 1000; // the first three hits are now outside the window
    expect([l.take("a"), l.take("a"), l.take("a"), l.take("a")]).toEqual([true, true, true, false]);
  });

  it("does not count refused hits, so a hammering client recovers on schedule", () => {
    let t = 0;
    const l = new SlidingWindowLimiter(1, 100, () => t);
    expect(l.take("k")).toBe(true);
    for (t = 1; t < 100; t++) expect(l.take("k")).toBe(false);
    t = 100;
    expect(l.take("k")).toBe(true);
  });

  it("forgets idle keys", () => {
    let t = 0;
    const l = new SlidingWindowLimiter(5, 10, () => t);
    for (let i = 0; i < 999; i++) l.take(`k${i}`);
    expect(l.size).toBe(999);
    t = 50;
    l.take("last"); // 1000th call prunes
    expect(l.size).toBe(1);
  });
});
