// Playwright runner (plan step 1.25 / 3.20): builds the bench page, serves it
// cross-origin isolated with `vite preview`, and runs it in Chromium, Firefox
// and WebKit, each in N fresh browser launches.
//
//   npm run bench                         # 5 runs x 3 browsers, full method
//   npm run bench:quick                   # 1 run x 3 browsers, quick config
//   npx tsx scripts/run-bench.ts --browsers chromium --runs 3 --mode main --filter 'E1/ML-KEM-768'
//   npx tsx scripts/run-bench.ts --headed --out results/my-run

import { build, preview } from 'vite';
import { chromium, firefox, webkit, type BrowserType } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { parseArgs } from 'node:util';

const ROOT = resolve(import.meta.dirname, '..');
const { values: args } = parseArgs({
  options: {
    browsers: { type: 'string', default: 'chromium,firefox,webkit' },
    runs: { type: 'string', default: '5' },
    quick: { type: 'boolean', default: false },
    mode: { type: 'string', default: 'worker' },
    filter: { type: 'string' },
    batches: { type: 'string' },
    out: { type: 'string' },
    headed: { type: 'boolean', default: false },
    'no-build': { type: 'boolean', default: false },
    'timeout-min': { type: 'string', default: '45' },
  },
});

const TYPES: Record<string, BrowserType> = { chromium, firefox, webkit };
const today = new Date().toISOString().slice(0, 10);
const outDir = resolve(ROOT, args.out ?? `results/${today}`);
const runs = Number(args.runs);
const timeout = Number(args['timeout-min']) * 60_000;

async function main() {
  const configFile = resolve(ROOT, 'vite.config.ts');
  if (!args['no-build']) {
    console.log('[bench] building page…');
    await build({ configFile, logLevel: 'warn' });
  }
  const server = await preview({ configFile, preview: { port: 4174, strictPort: false, host: '127.0.0.1' } });
  const base = server.resolvedUrls?.local[0];
  if (!base) throw new Error('vite preview did not report a URL');
  console.log(`[bench] serving ${base} (COOP/COEP on)`);
  await mkdir(outDir, { recursive: true });

  const q = new URLSearchParams({ mode: args.mode! });
  if (args.quick) q.set('quick', '1');
  if (args.filter) q.set('filter', args.filter);
  if (args.batches) q.set('batches', args.batches);
  const url = `${base}?${q}`;

  const failures: string[] = [];
  try {
    for (const name of args.browsers!.split(',').map((s) => s.trim()).filter(Boolean)) {
      const type = TYPES[name];
      if (!type) throw new Error(`unknown browser ${name}`);
      for (let run = 1; run <= runs; run++) {
        const label = `${name}-${run}`;
        const t0 = Date.now();
        // Fresh launch per run: no shared JIT state, caches or GC history.
        let browser: Awaited<ReturnType<BrowserType['launch']>> | undefined;
        try {
          browser = await type.launch({ headless: !args.headed });
          const page = await browser.newPage();
          page.on('pageerror', (e) => console.error(`[${label}] pageerror: ${e.message}`));
          await page.goto(url);
          let last = '';
          const poll = setInterval(async () => {
            const p = await page.evaluate(() => window.__progress).catch(() => undefined);
            const line = p ? `${p.done}/${p.total} ${p.last}` : '';
            if (line && line !== last) {
              last = line;
              process.stdout.write(`\r[${label}] ${line}`.padEnd(100));
            }
          }, 1000);
          try {
            await page.waitForFunction(() => window.__done === true || !!window.__error, null, { timeout, polling: 500 });
          } finally {
            clearInterval(poll);
            process.stdout.write('\n');
          }
          const err = await page.evaluate(() => window.__error);
          if (err) throw new Error(err);
          const doc = await page.evaluate(() => window.__results);
          const file = resolve(outDir, `${label}.json`);
          await writeFile(
            file,
            JSON.stringify({ ...doc, runner: { browser: name, browserVersion: browser!.version(), run, headless: !args.headed, url } }, null, 1),
          );
          const nOk = doc!.results.filter((r) => r.status === 'ok').length;
          console.log(
            `[${label}] ${nOk}/${doc!.results.length} ok, COI=${doc!.env.crossOriginIsolated}, ` +
              `timer≈${(doc!.env.timerResolutionUs as number).toFixed(1)}µs, ${((Date.now() - t0) / 1000).toFixed(0)}s -> ${relative(ROOT, file)}`,
          );
        } catch (e) {
          failures.push(`${label}: ${(e as Error).message}`);
          console.error(`[${label}] FAILED: ${(e as Error).message}`);
        } finally {
          await browser?.close();
        }
      }
    }
  } finally {
    await new Promise<void>((r) => server.httpServer.close(() => r()));
  }
  if (failures.length) {
    console.error(`[bench] ${failures.length} run(s) failed:\n  ${failures.join('\n  ')}`);
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
