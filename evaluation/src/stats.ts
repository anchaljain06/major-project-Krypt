// Robust summary statistics for benchmark batches.
// Every number reported by the harness comes from here, so browser and Node
// results are computed identically.

export interface Summary {
  n: number; // number of batches
  median: number; // ns/op
  p5: number;
  p95: number;
  q1: number;
  q3: number;
  iqr: number;
  min: number;
  max: number;
  mean: number; // reported for completeness only; never used alone
  ciLow: number; // bootstrap 95% CI of the median
  ciHigh: number;
  bootstrapResamples: number;
}

/** Linear-interpolated quantile (type 7, same as numpy's default). `sorted` must be ascending. */
export function quantile(sorted: ArrayLike<number>, q: number): number {
  const n = sorted.length;
  if (n === 0) return NaN;
  if (n === 1) return sorted[0];
  const pos = (n - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

/** Quantile of unsorted values (sorts a copy). NaN for an empty list. */
export function quantileOf(values: readonly number[], q: number): number {
  return quantile(Float64Array.from(values).sort(), q);
}

/** Arithmetic mean. NaN for an empty list. */
export function mean(values: readonly number[]): number {
  return values.length ? values.reduce((s, x) => s + x, 0) / values.length : NaN;
}

/** Small, seedable PRNG (mulberry32) so bootstrap CIs are reproducible. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Percentile bootstrap 95% CI of the median. */
export function bootstrapMedianCI(
  values: number[],
  resamples = 10_000,
  seed = 0x4b525950, // "KRYP"
): [number, number] {
  const n = values.length;
  if (n === 0) return [NaN, NaN];
  const rand = mulberry32(seed);
  const meds = new Float64Array(resamples);
  const buf = new Float64Array(n);
  for (let r = 0; r < resamples; r++) {
    for (let i = 0; i < n; i++) buf[i] = values[(rand() * n) | 0];
    buf.sort();
    meds[r] = quantile(buf, 0.5);
  }
  meds.sort();
  return [quantile(meds, 0.025), quantile(meds, 0.975)];
}

export function summarize(values: number[], resamples = 10_000): Summary {
  const s = Float64Array.from(values).sort();
  const q1 = quantile(s, 0.25);
  const q3 = quantile(s, 0.75);
  const [ciLow, ciHigh] = bootstrapMedianCI(values, resamples);
  let sum = 0;
  for (const v of values) sum += v;
  return {
    n: values.length,
    median: quantile(s, 0.5),
    p5: quantile(s, 0.05),
    p95: quantile(s, 0.95),
    q1,
    q3,
    iqr: q3 - q1,
    min: s[0],
    max: s[s.length - 1],
    mean: sum / values.length,
    ciLow,
    ciHigh,
    bootstrapResamples: resamples,
  };
}
