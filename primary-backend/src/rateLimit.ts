// In-memory sliding-window counter.
//
// Used to stop one requester from draining another user's one-time prekeys:
// each GET /api/bundle/:username claims an OPK, so without a limit a single
// account could empty a target's supply in a loop and force every later
// handshake onto the signed prekey. Over the limit the bundle is still
// served, just without an OPK (the X3DH-style SPK-only fallback).
//
// State lives in this process only. Render runs one instance; with several,
// each would allow its own quota, which is still a bound.

export class SlidingWindowLimiter {
  private readonly hits = new Map<string, number[]>();
  private calls = 0;

  constructor(
    readonly limit: number,
    readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Records a hit for `key` and returns true if it is within the limit. Over the limit nothing is recorded. */
  take(key: string): boolean {
    const t = this.now();
    const fresh = (this.hits.get(key) ?? []).filter((x) => t - x < this.windowMs);
    const ok = fresh.length < this.limit;
    if (ok) fresh.push(t);
    if (fresh.length) this.hits.set(key, fresh);
    else this.hits.delete(key);
    if (++this.calls % 1000 === 0) this.prune(t);
    return ok;
  }

  /** Number of keys tracked (tests). */
  get size(): number {
    return this.hits.size;
  }

  private prune(t: number) {
    for (const [k, v] of this.hits) {
      if (v.every((x) => t - x >= this.windowMs)) this.hits.delete(k);
    }
  }
}
