// Dedicated Web Worker: runs the suite off the main thread so rendering,
// GC of the page and input handling do not land inside timed batches.
import { runSuite, type RunOptions } from '../src/run.ts';

self.onmessage = async (ev: MessageEvent<{ quick: boolean; filter: string | null; overrides?: RunOptions['overrides'] }>) => {
  try {
    const doc = await runSuite({
      ...ev.data,
      context: 'worker',
      onProgress: (done, total, r) => self.postMessage({ type: 'progress', done, total, result: r }),
    });
    self.postMessage({ type: 'done', doc });
  } catch (e) {
    self.postMessage({ type: 'error', error: String((e as Error)?.stack ?? e) });
  }
};
