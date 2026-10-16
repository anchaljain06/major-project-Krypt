// Batch timer implementing the method rules of strategy section 6.1:
//   - discard >= 100 warm-up calls (50 in quick mode, still inside the 50-200 rule)
//   - size each batch so it lasts >= minBatchMs (10 ms) on this machine
//   - take >= 30 batches; report median, p95, IQR and a bootstrap 95% CI
// One timing sample = (batch wall time) / (calls in batch), in ns/op.
// Works unchanged in a Web Worker, on the main thread, and in Node.

import { Bench } from 'tinybench';
import { summarize, type Summary } from './stats.ts';

export interface BenchConfig {
  warmupCalls: number;
  minBatchMs: number;
  batches: number;
  bootstrapResamples: number;
  /** Upper bound on wall time spent timing one op (ms); protects against pathological backends. */
  maxOpMs: number;
  /** Also run tinybench (per-call sampling) as a cross-check. */
  tinybench: boolean;
}

export const FULL_CONFIG: BenchConfig = {
  warmupCalls: 100,
  minBatchMs: 10,
  batches: 30,
  bootstrapResamples: 10_000,
  maxOpMs: 20_000,
  tinybench: true,
};

export const QUICK_CONFIG: BenchConfig = {
  warmupCalls: 50,
  minBatchMs: 10,
  batches: 12,
  bootstrapResamples: 10_000,
  maxOpMs: 5_000,
  tinybench: false,
};

export type OpFn = () => unknown | Promise<unknown>;

export interface TinybenchCheck {
  p50Ns: number;
  meanNs: number;
  rmePct: number;
  samples: number;
}

export interface Measurement {
  stats: Summary;
  batchSize: number;
  warmupCalls: number;
  batchesNs: number[]; // raw per-batch ns/op, kept so analysis can re-bootstrap
  tinybench?: TinybenchCheck;
}

// Prevent dead-code elimination of results.
let sink: unknown;
export const getSink = () => sink;

async function timeBatch(fn: OpFn, n: number, isAsync: boolean): Promise<number> {
  if (isAsync) {
    const t0 = performance.now();
    for (let i = 0; i < n; i++) sink = await fn();
    return performance.now() - t0;
  }
  const t0 = performance.now();
  for (let i = 0; i < n; i++) sink = fn();
  return performance.now() - t0;
}

export async function measure(fn: OpFn, isAsync: boolean, cfg: BenchConfig): Promise<Measurement> {
  const opStart = performance.now();
  // 1. Warm-up (discarded): JIT tiers, WASM instantiation, lazy tables.
  await timeBatch(fn, cfg.warmupCalls, isAsync);

  // 2. Calibrate batch size: double until one batch takes >= minBatchMs.
  let n = 1;
  for (;;) {
    const ms = await timeBatch(fn, n, isAsync);
    if (ms >= cfg.minBatchMs || n >= 1 << 22) break;
    // Jump close to the target once we have a usable estimate.
    n = ms > 0.5 ? Math.max(n * 2, Math.ceil((n * cfg.minBatchMs * 1.2) / ms)) : n * 2;
  }

  // 3. Timed batches.
  const batchesNs: number[] = [];
  for (let b = 0; b < cfg.batches; b++) {
    const ms = await timeBatch(fn, n, isAsync);
    batchesNs.push((ms * 1e6) / n);
    if (performance.now() - opStart > cfg.maxOpMs && batchesNs.length >= 5) break;
  }

  const out: Measurement = {
    stats: summarize(batchesNs, cfg.bootstrapResamples),
    batchSize: n,
    warmupCalls: cfg.warmupCalls,
    batchesNs,
  };

  if (cfg.tinybench) out.tinybench = await tinybenchCheck(fn);
  return out;
}

async function tinybenchCheck(fn: OpFn): Promise<TinybenchCheck | undefined> {
  try {
    const bench = new Bench({ time: 300, warmupTime: 50, iterations: 32 });
    bench.add('op', fn);
    await bench.run();
    const r = bench.tasks[0].result as unknown as {
      latency?: { p50: number; mean: number; rme: number; samplesCount: number };
    };
    if (!r.latency) return undefined;
    return {
      p50Ns: r.latency.p50 * 1e6,
      meanNs: r.latency.mean * 1e6,
      rmePct: r.latency.rme,
      samples: r.latency.samplesCount,
    };
  } catch {
    return undefined;
  }
}

/** Smallest observable positive step of performance.now(), in microseconds. */
export function estimateTimerResolutionUs(samples = 2000): number {
  let best = Infinity;
  for (let i = 0; i < samples; i++) {
    const a = performance.now();
    let b = performance.now();
    let guard = 0;
    while (b === a && guard++ < 1e6) b = performance.now();
    if (b > a) best = Math.min(best, b - a);
  }
  return best * 1000;
}
