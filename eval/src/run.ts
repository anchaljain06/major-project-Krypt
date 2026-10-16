// Runs the whole suite in the current JS context (Web Worker, page main
// thread, or Node) and returns one JSON-serialisable results document.

import { estimateTimerResolutionUs, FULL_CONFIG, QUICK_CONFIG, type BenchConfig } from './harness.ts';
import { allOps, detectNativeSupport, runAll, type OpResult, type OpSpec } from './experiments.ts';

export const SCHEMA = 'krypt-bench/1';

export interface RunOptions {
  quick: boolean;
  filter: string | null;
  context: 'worker' | 'main' | 'node';
  extraOps?: OpSpec[];
  extraEnv?: Record<string, unknown>;
  overrides?: Partial<BenchConfig>;
  onProgress?: (done: number, total: number, r: OpResult) => void;
}

export interface ResultsDoc {
  schema: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  config: BenchConfig & { quick: boolean; filter: string | null };
  env: Record<string, unknown>;
  results: OpResult[];
}

export function collectEnv(context: RunOptions['context']): Record<string, unknown> {
  const nav = (globalThis as { navigator?: Navigator & { deviceMemory?: number } }).navigator;
  return {
    context,
    crossOriginIsolated: (globalThis as { crossOriginIsolated?: boolean }).crossOriginIsolated ?? null,
    isSecureContext: (globalThis as { isSecureContext?: boolean }).isSecureContext ?? null,
    userAgent: nav?.userAgent ?? null,
    hardwareConcurrency: nav?.hardwareConcurrency ?? null,
    deviceMemoryGB: nav?.deviceMemory ?? null,
    timerResolutionUs: estimateTimerResolutionUs(),
    webassembly: typeof WebAssembly === 'object',
    wasmSimd: wasmSimdSupported(),
    nativeWebCrypto: detectNativeSupport(),
  };
}

function wasmSimdSupported(): boolean {
  try {
    // Minimal module using v128 (from wasm-feature-detect).
    return WebAssembly.validate(
      new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253, 15, 253, 98, 11]),
    );
  } catch {
    return false;
  }
}

export async function runSuite(opts: RunOptions): Promise<ResultsDoc> {
  const cfg: BenchConfig = { ...(opts.quick ? QUICK_CONFIG : FULL_CONFIG), ...opts.overrides };
  const env = { ...collectEnv(opts.context), ...opts.extraEnv };
  const startedAt = new Date().toISOString();
  const t0 = performance.now();
  const results = await runAll(allOps(opts.extraOps), cfg, opts.filter ? new RegExp(opts.filter) : null, opts.onProgress);
  return {
    schema: SCHEMA,
    startedAt,
    finishedAt: new Date().toISOString(),
    durationMs: performance.now() - t0,
    config: { ...cfg, quick: opts.quick, filter: opts.filter },
    env,
    results,
  };
}
