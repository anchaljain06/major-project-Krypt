/**
 * Phase E benchmarks in the real app (plan E.4, new-plan section 12), driven by
 * evaluation/files-bench/run.mjs against a production build and the real relay.
 * BENCH picks one; each writes JSON to BENCH_OUT.
 *
 *   chunks   BENCH_FILE_MIB file, Alice -> Bob, BENCH_RUNS fresh pairs. Accept-to-done time,
 *            peak heap, chunk frames sent (retries), long tasks on both pages, bytes verified.
 *            The chunk size is whatever the build was made with (VITE_FILE_CHUNK_SIZE).
 *   resume   Bob's socket is cut once Alice has sent half the chunks and kept down for
 *            BENCH_DOWN_MS. Retransmitted bytes, completion, and per chunk: one nonce counter
 *            and identical ciphertext on every send.
 *   session  Register both, befriend, first message (handshake), 100 alternating messages,
 *            one BENCH_FILE_MIB file. Time and bytes per phase.
 *
 * Bytes are counted in the browser: WebSocket frame payloads plus HTTP headers and bodies
 * to the API (long-polling included). WebSocket framing and TCP/TLS are not counted.
 */
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { expect, test, type Browser, type Page, type WebSocketRoute } from "@playwright/test";
import { befriend, newUser, openChat, register, type User } from "./helpers";

const BENCH = process.env.BENCH ?? "";
const OUT = resolve(process.env.BENCH_OUT ?? "test-results/bench.json");
const RUNS = Number(process.env.BENCH_RUNS ?? 3);
const FILE_MIB = Number(process.env.BENCH_FILE_MIB ?? 100);
const DOWN_MS = Number(process.env.BENCH_DOWN_MS ?? 2000);
const API = process.env.VITE_API_URL ?? "http://localhost:3100";
const MiB = 1024 * 1024;
const tag = Date.now().toString(36).slice(-5);

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const card = (page: Page, name: string) => page.getByTestId("file-transfer").filter({ hasText: name });
const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor((xs.length - 1) / 2)] ?? NaN;

// ---------------------------------------------------------------------------
// Instruments

interface SentChunk {
  index: number;
  nonceCounter: number;
  bytes: number;
  sha: string;
}

interface Meter {
  wsUp: number;
  wsDown: number;
  httpUp: number;
  httpDown: number;
  /** file:chunk frames this page sent, in order. */
  chunks: SentChunk[];
}

const CHUNK_PACKET = /^451-\d*\["file:chunk",/;

/** Counts this page's traffic to the API and records each file:chunk it sends. */
function meter(page: Page): Meter {
  const m: Meter = { wsUp: 0, wsDown: 0, httpUp: 0, httpDown: 0, chunks: [] };
  let pending: Omit<SentChunk, "bytes" | "sha"> | null = null;
  page.on("websocket", (ws) => {
    ws.on("framesent", ({ payload }) => {
      if (typeof payload === "string") {
        m.wsUp += Buffer.byteLength(payload);
        if (CHUNK_PACKET.test(payload)) {
          const [, f] = JSON.parse(payload.slice(payload.indexOf("["))) as [string, { index: number; nonceCounter: number }];
          pending = { index: f.index, nonceCounter: f.nonceCounter };
        }
      } else {
        m.wsUp += payload.length;
        if (pending) m.chunks.push({ ...pending, bytes: payload.length, sha: sha(payload) });
        pending = null;
      }
    });
    ws.on("framereceived", ({ payload }) => {
      m.wsDown += typeof payload === "string" ? Buffer.byteLength(payload) : payload.length;
    });
  });
  page.on("requestfinished", async (req) => {
    if (!req.url().startsWith(API)) return;
    const s = await req.sizes();
    m.httpUp += s.requestHeadersSize + s.requestBodySize;
    m.httpDown += s.responseHeadersSize + s.responseBodySize;
  });
  return m;
}

const traffic = (ms: Meter[]) => ({
  wsUp: ms.reduce((n, m) => n + m.wsUp, 0),
  wsDown: ms.reduce((n, m) => n + m.wsDown, 0),
  httpUp: ms.reduce((n, m) => n + m.httpUp, 0),
  httpDown: ms.reduce((n, m) => n + m.httpDown, 0),
});
const minus = (a: ReturnType<typeof traffic>, b: ReturnType<typeof traffic>) => ({
  wsUp: a.wsUp - b.wsUp,
  wsDown: a.wsDown - b.wsDown,
  httpUp: a.httpUp - b.httpUp,
  httpDown: a.httpDown - b.httpDown,
});

/** Long tasks (> 50 ms on the main thread) from page load on. */
async function watchLongTasks(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __longTasks: [number, number][] };
    w.__longTasks = [];
    new PerformanceObserver((l) => {
      for (const e of l.getEntries()) w.__longTasks.push([e.startTime, e.duration]);
    }).observe({ type: "longtask", buffered: true });
  });
}
const pageNow = (page: Page) => page.evaluate(() => performance.now());
async function longTasksSince(page: Page, t0: number) {
  const all = await page.evaluate(() => (window as unknown as { __longTasks: [number, number][] }).__longTasks);
  const d = all.filter(([t]) => t >= t0).map(([, ms]) => ms);
  return { count: d.length, totalMs: d.reduce((a, b) => a + b, 0), maxMs: d.length ? Math.max(...d) : 0 };
}

/** Samples V8 heap use every 50 ms through CDP; `stop()` returns the baseline and the peak. */
async function heapSampler(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("HeapProfiler.collectGarbage");
  type Usage = { usedSize: number; backingStorageSize?: number };
  const read = async () => {
    const h = (await cdp.send("Runtime.getHeapUsage")) as Usage;
    return { js: h.usedSize, buffers: h.backingStorageSize ?? NaN };
  };
  const base = await read();
  const peak = { ...base };
  let running = true;
  const loop = (async () => {
    while (running) {
      const h = await read().catch(() => null);
      if (h) {
        peak.js = Math.max(peak.js, h.js);
        peak.buffers = Math.max(peak.buffers, h.buffers);
      }
      await new Promise((r) => setTimeout(r, 50));
    }
  })();
  return {
    async stop() {
      running = false;
      await loop;
      await cdp.detach();
      return { baseJs: base.js, peakJs: peak.js, baseBuffers: base.buffers, peakBuffers: peak.buffers };
    },
  };
}

/** Resolves when the card's status attribute becomes `status` (10 ms polling, not expect's back-off). */
function statusIs(page: Page, name: string, status: string, timeout = 600_000) {
  return page.waitForFunction(
    ([n, s]) =>
      [...document.querySelectorAll<HTMLElement>('[data-testid="file-transfer"]')].some(
        (el) => el.textContent?.includes(n) && el.dataset.status === s,
      ),
    [name, status] as const,
    { polling: 10, timeout },
  );
}

function textShown(page: Page, text: string) {
  return page.waitForFunction(
    (t) => [...document.querySelectorAll('[data-testid="message"]')].some((el) => el.textContent?.includes(t)),
    text,
    { polling: 10, timeout: 60_000 },
  );
}

// ---------------------------------------------------------------------------
// Setup

interface Pair {
  alice: User;
  bob: User;
  ma: Meter;
  mb: Meter;
}

/** Two fresh users with meters and long-task observers; `beforeRegister` can add routes. */
async function pair(browser: Browser, id: string, beforeRegister?: (p: Pair) => Promise<void>): Promise<Pair> {
  const alice = await newUser(browser, `ba${id}_${tag}`);
  const bob = await newUser(browser, `bb${id}_${tag}`);
  const p = { alice, bob, ma: meter(alice.page), mb: meter(bob.page) };
  await watchLongTasks(alice.page);
  await watchLongTasks(bob.page);
  await beforeRegister?.(p);
  return p;
}

async function connect({ alice, bob }: Pair) {
  await register(alice);
  await register(bob);
  await befriend(alice, bob);
  await openChat(alice, bob.name);
  await openChat(bob, alice.name);
}

async function randomFile(name: string, mib: number) {
  const path = resolve("test-results", "bench", name);
  await mkdir(dirname(path), { recursive: true });
  const bytes = randomBytes(mib * MiB);
  await writeFile(path, bytes);
  return { path, name, bytes };
}

async function offerAndWait(p: Pair, f: { path: string; name: string }) {
  await p.alice.page.locator("#file-upload").setInputFiles(f.path);
  await statusIs(p.bob.page, f.name, "offered", 60_000);
}

async function downloadSha(u: User, name: string) {
  const pending = u.page.waitForEvent("download");
  await card(u.page, name).getByRole("button", { name: "Download" }).click();
  return sha(await readFile((await (await pending).path())!));
}

async function save(data: Record<string, unknown>, browser: Browser) {
  await mkdir(dirname(OUT), { recursive: true });
  const env = { browser: "chromium", browserVersion: browser.version(), date: new Date().toISOString(), fileMiB: FILE_MIB, runs: RUNS };
  await writeFile(OUT, JSON.stringify({ bench: BENCH, env, ...data }, null, 1) + "\n");
}

const close = async (p: Pair) => {
  await p.alice.context.close();
  await p.bob.context.close();
};

// ---------------------------------------------------------------------------
// Benchmarks

test("bench: file chunk size", async ({ browser }) => {
  test.skip(BENCH !== "chunks");
  const runs = [];
  for (let run = 1; run <= RUNS; run++) {
    const p = await pair(browser, `c${run}`);
    await connect(p);
    const f = await randomFile(`chunks-${run}.bin`, FILE_MIB);
    await offerAndWait(p, f);

    const heaps = [await heapSampler(p.alice.page), await heapSampler(p.bob.page)];
    const t0 = [await pageNow(p.alice.page), await pageNow(p.bob.page)];
    const sentBefore = p.ma.chunks.length;
    const start = performance.now();
    await card(p.bob.page, f.name).getByRole("button", { name: "Accept file" }).click();
    await Promise.all([statusIs(p.alice.page, f.name, "complete"), statusIs(p.bob.page, f.name, "complete")]);
    const ms = performance.now() - start;
    const [ha, hb] = [await heaps[0]!.stop(), await heaps[1]!.stop()];
    const sent = p.ma.chunks.slice(sentBefore);
    const chunkCount = new Set(sent.map((c) => c.index)).size;

    runs.push({
      run,
      ms,
      mibPerS: FILE_MIB / (ms / 1000),
      chunkCount,
      framesSent: sent.length,
      retries: sent.length - chunkCount,
      chunkPayloadBytes: sent.reduce((n, c) => n + c.bytes, 0),
      heap: { alice: ha, bob: hb },
      longTasks: { alice: await longTasksSince(p.alice.page, t0[0]!), bob: await longTasksSince(p.bob.page, t0[1]!) },
      bytesMatch: (await downloadSha(p.bob, f.name)) === sha(f.bytes),
    });
    console.log(`run ${run}: ${ms.toFixed(0)} ms, ${chunkCount} chunks, ${sent.length - chunkCount} retries`);
    await close(p);
    await rm(f.path);
  }
  await save({ runs, medianMs: median(runs.map((r) => r.ms)) }, browser);
  expect(runs.every((r) => r.bytesMatch)).toBe(true);
});

test("bench: resume after the receiver disconnects", async ({ browser }) => {
  test.skip(BENCH !== "resume");
  const runs = [];
  for (let run = 1; run <= RUNS; run++) {
    // Bob's socket goes through a Playwright route so the test can cut it and keep it down.
    let blocked = false;
    let live: WebSocketRoute[] = [];
    const p = await pair(browser, `r${run}`, async ({ bob }) => {
      await bob.page.routeWebSocket(/\/socket\.io\//, (ws) => {
        if (blocked) return void ws.close();
        ws.connectToServer();
        live.push(ws);
      });
      await bob.page.route(/\/socket\.io\//, (r) => (blocked ? r.abort() : r.continue()));
    });
    await connect(p);
    const f = await randomFile(`resume-${run}.bin`, FILE_MIB);
    await offerAndWait(p, f);
    const sentBefore = p.ma.chunks.length;
    const start = performance.now();
    await card(p.bob.page, f.name).getByRole("button", { name: "Accept file" }).click();

    const expected = Math.ceil((FILE_MIB * MiB) / Number(process.env.BENCH_CHUNK_BYTES ?? MiB));
    await expect.poll(() => p.ma.chunks.length - sentBefore, { intervals: [10], timeout: 120_000 }).toBeGreaterThanOrEqual(expected / 2);
    blocked = true;
    const cutAt = p.ma.chunks.length - sentBefore;
    for (const ws of live) await ws.close();
    live = [];
    await new Promise((r) => setTimeout(r, DOWN_MS));
    const alicePaused = (await card(p.alice.page, f.name).getAttribute("data-status")) === "paused";
    blocked = false;
    const reopened = performance.now();

    let completed = true;
    await Promise.all([statusIs(p.alice.page, f.name, "complete", 180_000), statusIs(p.bob.page, f.name, "complete", 180_000)]).catch(
      () => (completed = false),
    );
    const done = performance.now();

    const sent = p.ma.chunks.slice(sentBefore);
    const byIndex = new Map<number, SentChunk[]>();
    for (const c of sent) byIndex.set(c.index, [...(byIndex.get(c.index) ?? []), c]);
    const counterOwner = new Map<number, number>();
    let counterReused = false;
    for (const c of sent) {
      if ((counterOwner.get(c.nonceCounter) ?? c.index) !== c.index) counterReused = true;
      counterOwner.set(c.nonceCounter, c.index);
    }
    const resent = [...byIndex.values()].filter((cs) => cs.length > 1);
    runs.push({
      run,
      chunkCount: byIndex.size,
      cutAfterChunksSent: cutAt,
      alicePausedDuringOutage: alicePaused,
      completed,
      bytesMatch: completed && (await downloadSha(p.bob, f.name)) === sha(f.bytes),
      totalMs: done - start,
      resumeMs: done - reopened,
      framesSent: sent.length,
      chunksResent: resent.length,
      retransmittedBytes: resent.reduce((n, cs) => n + cs.slice(1).reduce((m, c) => m + c.bytes, 0), 0),
      oneCounterPerChunk: [...byIndex.values()].every((cs) => new Set(cs.map((c) => c.nonceCounter)).size === 1),
      identicalResends: resent.every((cs) => new Set(cs.map((c) => c.sha)).size === 1),
      counterReused,
    });
    console.log(`run ${run}: cut at ${cutAt}, resent ${resent.length}, completed ${completed}`);
    await close(p);
    await rm(f.path);
  }
  await save({ downMs: DOWN_MS, runs }, browser);
  expect(runs.every((r) => r.completed && r.bytesMatch && r.oneCounterPerChunk && r.identicalResends && !r.counterReused)).toBe(true);
});

test("bench: first session, 100 messages and a file", async ({ browser }) => {
  test.skip(BENCH !== "session");
  const runs = [];
  for (let run = 1; run <= RUNS; run++) {
    const p = await pair(browser, `s${run}`);
    const meters = [p.ma, p.mb];
    const phases: Record<string, { ms: number } & ReturnType<typeof traffic>> = {};
    const phase = async (name: string, fn: () => Promise<void>) => {
      const before = traffic(meters);
      const t = performance.now();
      await fn();
      const ms = performance.now() - t;
      await new Promise((r) => setTimeout(r, 300)); // let requestfinished handlers settle
      phases[name] = { ms, ...minus(traffic(meters), before) };
    };
    const say = async (from: User, to: User, text: string) => {
      const input = from.page.getByPlaceholder(/Secure message to/);
      await input.fill(text);
      await input.press("Enter");
      await textShown(to.page, text);
    };

    await phase("register", async () => {
      await register(p.alice);
      await register(p.bob);
    });
    await phase("befriend", async () => {
      await befriend(p.alice, p.bob);
      await openChat(p.alice, p.bob.name);
      await openChat(p.bob, p.alice.name);
    });
    await phase("firstMessage", () => say(p.alice, p.bob, `first-${run}.`));
    await phase("messages100", async () => {
      for (let i = 1; i <= 100; i++) {
        if (i % 2) await say(p.bob, p.alice, `m-${run}-${i}.`);
        else await say(p.alice, p.bob, `m-${run}-${i}.`);
      }
    });
    const f = await randomFile(`session-${run}.bin`, FILE_MIB);
    await phase("file", async () => {
      await offerAndWait(p, f);
      await card(p.bob.page, f.name).getByRole("button", { name: "Accept file" }).click();
      await Promise.all([statusIs(p.alice.page, f.name, "complete"), statusIs(p.bob.page, f.name, "complete")]);
    });
    const total = Object.values(phases).reduce(
      (a, x) => ({ ms: a.ms + x.ms, wsUp: a.wsUp + x.wsUp, wsDown: a.wsDown + x.wsDown, httpUp: a.httpUp + x.httpUp, httpDown: a.httpDown + x.httpDown }),
      { ms: 0, wsUp: 0, wsDown: 0, httpUp: 0, httpDown: 0 },
    );
    const bytesMatch = (await downloadSha(p.bob, f.name)) === sha(f.bytes);
    runs.push({ run, phases, total, bytesMatch, problems: [...p.alice.problems, ...p.bob.problems] });
    console.log(`run ${run}: ${(total.ms / 1000).toFixed(1)} s`);
    await close(p);
    await rm(f.path);
  }
  await save({ runs }, browser);
  expect(runs.every((r) => r.bytesMatch && r.problems.length === 0)).toBe(true);
});
