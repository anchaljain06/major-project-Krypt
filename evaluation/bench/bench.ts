// Page controller. Runs the suite in a dedicated worker (default) or on the
// main thread (?mode=main), renders a summary table, and publishes the full
// results document on window.__results for the Playwright runner or for a
// human to copy (real Safari, Android via chrome://inspect).
import { collectEnv, runSuite, type ResultsDoc } from '../src/run.ts';
import type { OpResult } from '../src/experiments.ts';

declare global {
  interface Window {
    __results?: ResultsDoc & { pageEnv: Record<string, unknown> };
    __done?: boolean;
    __error?: string;
    __progress?: { done: number; total: number; last?: string };
  }
}

const params = new URLSearchParams(location.search);
const mode = params.get('mode') === 'main' ? 'main' : 'worker';
const quick = params.get('quick') === '1';
const filter = params.get('filter');
const batches = params.get('batches');
const overrides = batches ? { batches: Number(batches) } : undefined;

const $ = (id: string) => document.getElementById(id)!;
const fmtNs = (ns?: number) =>
  ns === undefined ? '' : ns >= 1e6 ? `${(ns / 1e6).toFixed(2)} ms` : ns >= 1e3 ? `${(ns / 1e3).toFixed(1)} µs` : `${ns.toFixed(0)} ns`;

function addRow(r: OpResult) {
  const tr = document.createElement('tr');
  const s = r.measurement?.stats;
  const cells = [
    r.id,
    r.status === 'ok' ? 'ok' : `${r.status}: ${r.reason ?? ''}`,
    fmtNs(s?.median),
    fmtNs(s?.p95),
    s ? `${fmtNs(s.ciLow)} – ${fmtNs(s.ciHigh)}` : '',
    s ? (r.mbpsMedian !== undefined ? `${r.mbpsMedian.toFixed(0)} MB/s` : (1e9 / s.median).toFixed(0)) : '',
    r.measurement ? String(r.measurement.batchSize) : '',
  ];
  cells.forEach((c, i) => {
    const td = document.createElement('td');
    td.textContent = c;
    if (i >= 2) td.className = 'num';
    if (i === 1 && r.status !== 'ok') td.className = 'bad';
    tr.appendChild(td);
  });
  $('rows').appendChild(tr);
}

function finish(doc: ResultsDoc, pageEnv: Record<string, unknown>) {
  window.__results = { ...doc, pageEnv };
  window.__done = true;
  $('status').textContent = `done: ${doc.results.length} ops in ${(doc.durationMs / 1000).toFixed(1)} s (${mode})`;
  const json = JSON.stringify(window.__results);
  const copy = $('copy') as HTMLButtonElement;
  copy.disabled = false;
  copy.onclick = () => navigator.clipboard.writeText(json).then(() => (copy.textContent = 'Copied'));
  const a = $('download') as HTMLAnchorElement;
  a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  a.download = `krypt-bench-${Date.now()}.json`;
  a.hidden = false;
}

function progress(done: number, total: number, r: OpResult) {
  window.__progress = { done, total, last: r.id };
  $('status').textContent = `running (${mode}${quick ? ', quick' : ''}): ${done}/${total} ${r.id}`;
  addRow(r);
}

async function run() {
  ($('run') as HTMLButtonElement).disabled = true;
  $('rows').textContent = '';
  window.__done = false;
  const pageEnv = collectEnv('main');
  $('env').textContent =
    `crossOriginIsolated=${pageEnv.crossOriginIsolated} · timer≈${(pageEnv.timerResolutionUs as number).toFixed(1)} µs · ` +
    `cores=${pageEnv.hardwareConcurrency} · ${pageEnv.userAgent}`;
  if (mode === 'main') {
    try {
      const doc = await runSuite({ quick, filter, overrides, context: 'main', onProgress: progress });
      finish(doc, pageEnv);
    } catch (e) {
      window.__error = String((e as Error)?.stack ?? e);
      $('status').textContent = `error: ${window.__error}`;
    }
    return;
  }
  const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
  worker.onmessage = (ev) => {
    const m = ev.data;
    if (m.type === 'progress') progress(m.done, m.total, m.result);
    else if (m.type === 'done') {
      finish(m.doc, pageEnv);
      worker.terminate();
    } else if (m.type === 'error') {
      window.__error = m.error;
      $('status').textContent = `error: ${m.error}`;
    }
  };
  worker.onerror = (ev) => {
    window.__error = `worker error: ${ev.message}`;
    $('status').textContent = window.__error;
  };
  worker.postMessage({ quick, filter, overrides });
}

$('run').addEventListener('click', run);
if (params.get('autorun') !== '0') run();
