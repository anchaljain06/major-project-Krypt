// Flatten a results directory into CSV tables for the plots and the report.
//
//   npx tsx scripts/aggregate.ts [results/<dir>]     (default: newest results/* dir)
//
// Writes into the same directory:
//   long.csv      one row per (file, op): every run, every statistic
//   summary.csv   one row per (source, op): median of run medians, between-run
//                 min/max, pooled-batch p5/p95/IQR and a bootstrap CI over pooled batches
//   env.csv       one row per file: browser, version, crossOriginIsolated, timer, UA
//   headline.md   ML-KEM-768 / ML-DSA-65 medians per source x backend

import { readdir, readFile, writeFile, stat } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { summarize, quantile } from '../src/stats.ts';
import type { ResultsDoc } from '../src/run.ts';

const ROOT = resolve(import.meta.dirname, '..');

type Doc = ResultsDoc & { runner?: { browser: string; browserVersion: string; run: number } };

async function newestDir(): Promise<string> {
  const base = resolve(ROOT, 'results');
  const dirs: { p: string; t: number }[] = [];
  for (const d of await readdir(base)) {
    const p = resolve(base, d);
    const s = await stat(p);
    if (s.isDirectory()) dirs.push({ p, t: s.mtimeMs });
  }
  if (!dirs.length) throw new Error('no results directories');
  return dirs.sort((a, b) => b.t - a.t)[0].p;
}

const csvCell = (v: unknown) => {
  if (v === undefined || v === null || (typeof v === 'number' && !Number.isFinite(v))) return '';
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const toCsv = (rows: Record<string, unknown>[]) => {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  return [cols.join(','), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\n') + '\n';
};

async function main() {
  const dir = process.argv[2] ? resolve(process.cwd(), process.argv[2]) : await newestDir();
  const files = (await readdir(dir)).filter((f) => f.endsWith('.json') && !f.startsWith('e5-'));
  const docs: { file: string; doc: Doc }[] = [];
  for (const f of files) {
    const doc = JSON.parse(await readFile(resolve(dir, f), 'utf8')) as Doc;
    if (doc.schema !== 'krypt-bench/1') continue;
    docs.push({ file: f, doc });
  }
  if (!docs.length) throw new Error(`no krypt-bench/1 files in ${dir}`);

  const long: Record<string, unknown>[] = [];
  const env: Record<string, unknown>[] = [];
  for (const { file, doc } of docs) {
    const source = doc.runner?.browser ?? String(doc.env.context);
    const run = doc.runner?.run ?? 1;
    env.push({
      file,
      source,
      version: doc.runner?.browserVersion,
      run,
      context: doc.env.context,
      quick: doc.config.quick,
      crossOriginIsolated: doc.env.crossOriginIsolated,
      timer_us: doc.env.timerResolutionUs,
      cores: doc.env.hardwareConcurrency,
      wasm_simd: doc.env.wasmSimd,
      native_supports_fn: (doc.env.nativeWebCrypto as { supportsFn: boolean })?.supportsFn,
      started: doc.startedAt,
      duration_s: (doc.durationMs / 1000).toFixed(1),
      ua: doc.env.userAgent,
    });
    for (const r of doc.results) {
      const s = r.measurement?.stats;
      long.push({
        source, run, exp: r.exp, family: r.family, alg: r.alg, op: r.op, bytes: r.bytes, backend: r.backend,
        status: r.status, reason: r.reason,
        median_ns: s?.median, p5_ns: s?.p5, p95_ns: s?.p95, q1_ns: s?.q1, q3_ns: s?.q3, iqr_ns: s?.iqr,
        ci_lo_ns: s?.ciLow, ci_hi_ns: s?.ciHigh, ops_s: s ? 1e9 / s.median : undefined, mbps: r.mbpsMedian,
        batches: s?.n, batch_size: r.measurement?.batchSize, tinybench_p50_ns: r.measurement?.tinybench?.p50Ns,
        coi: doc.env.crossOriginIsolated, timer_us: doc.env.timerResolutionUs,
      });
    }
  }

  // summary across runs
  const groups = new Map<string, { key: Record<string, unknown>; medians: number[]; pooled: number[]; statuses: Set<string>; reasons: Set<string> }>();
  for (const { doc } of docs) {
    const source = doc.runner?.browser ?? String(doc.env.context);
    for (const r of doc.results) {
      const k = [source, r.exp, r.alg, r.op, r.bytes ?? '', r.backend].join('|');
      const g = groups.get(k) ?? {
        key: { source, exp: r.exp, family: r.family, alg: r.alg, op: r.op, bytes: r.bytes, backend: r.backend },
        medians: [], pooled: [], statuses: new Set(), reasons: new Set(),
      };
      g.statuses.add(r.status);
      if (r.reason) g.reasons.add(r.reason);
      if (r.measurement) {
        g.medians.push(r.measurement.stats.median);
        g.pooled.push(...r.measurement.batchesNs);
      }
      groups.set(k, g);
    }
  }
  const summary: Record<string, unknown>[] = [];
  for (const g of groups.values()) {
    const ok = g.medians.length > 0;
    const med = ok ? quantile([...g.medians].sort((a, b) => a - b), 0.5) : undefined;
    const pooled = ok ? summarize(g.pooled, 2000) : undefined;
    const bytes = g.key.bytes as number | undefined;
    summary.push({
      ...g.key,
      status: ok ? 'ok' : [...g.statuses].join('/'),
      reason: ok ? '' : [...g.reasons][0],
      runs: g.medians.length,
      median_ns: med,
      run_min_ns: ok ? Math.min(...g.medians) : undefined,
      run_max_ns: ok ? Math.max(...g.medians) : undefined,
      p5_ns: pooled?.p5, p95_ns: pooled?.p95, iqr_ns: pooled?.iqr,
      ci_lo_ns: pooled?.ciLow, ci_hi_ns: pooled?.ciHigh,
      ops_s: med ? 1e9 / med : undefined,
      ops_s_p95: pooled ? 1e9 / pooled.p95 : undefined, // slow tail -> lower ops/s
      ops_s_p5: pooled ? 1e9 / pooled.p5 : undefined,
      mbps: med && bytes ? (bytes / med) * 1e3 : undefined,
    });
  }

  await writeFile(resolve(dir, 'long.csv'), toCsv(long));
  await writeFile(resolve(dir, 'summary.csv'), toCsv(summary));
  await writeFile(resolve(dir, 'env.csv'), toCsv(env));

  // Headline markdown table
  const fmt = (ns?: number) => (ns === undefined ? 'n/a' : ns >= 1e6 ? `${(ns / 1e6).toFixed(2)} ms` : `${(ns / 1e3).toFixed(1)} µs`);
  const sources = [...new Set(summary.map((r) => r.source as string))];
  const backends = ['noble', 'liboqs-wasm', 'webcrypto-native', 'node-crypto'];
  const lines: string[] = [];
  for (const [alg, ops] of [['ML-KEM-768', ['keygen', 'encaps', 'decaps']], ['ML-DSA-65', ['keygen', 'sign', 'verify']]] as const) {
    lines.push(`\n### ${alg} (median of run medians)\n`, `| source | op | ${backends.join(' | ')} |`, `|---|---|${backends.map(() => '---:').join('|')}|`);
    for (const src of sources)
      for (const op of ops) {
        const cells = backends.map((b) => {
          const r = summary.find((x) => x.source === src && x.alg === alg && x.op === op && x.backend === b);
          if (!r) return '–';
          return r.status === 'ok' ? fmt(r.median_ns as number) : 'unsupported';
        });
        lines.push(`| ${src} | ${op} | ${cells.join(' | ')} |`);
      }
  }
  await writeFile(resolve(dir, 'headline.md'), `# Headline numbers: ${relative(ROOT, dir)}\n${lines.join('\n')}\n`);
  console.log(`[aggregate] ${docs.length} files, ${long.length} rows -> ${relative(ROOT, dir)}/{long,summary,env}.csv, headline.md`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
