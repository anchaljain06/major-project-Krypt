// E5, file chunks (plan E.4, new-plan section 12 "Wire transport"): one encrypted
// `file:chunk` frame as the app sends it (a socket.io binary attachment) against
// the same frame with the chunk as a base64 string inside the JSON packet.
//
// Per chunk size (256 KiB, 1 MiB, 4 MiB) and encoding:
//   wire bytes     what one hop puts on the WebSocket: engine.io's 1-byte type prefix on the
//                  text packet + the binary attachment, if any. WebSocket framing (2-14 B per
//                  frame) is not counted. The relay re-sends the frame, so a transfer costs 2 hops.
//   encode, decode median and p95 per frame with the batch timer (src/harness.ts, full method):
//                  sender = socket.io-parser encode (+ base64 of the chunk);
//                  receiver = socket.io-parser decode (+ base64 decode back to bytes)
//   copies         bytes of payload-sized strings and buffers created per frame besides the
//                  chunk itself and the received WebSocket message, read off the real outputs
//
// The frame is real: a chunk encrypted by frontend/src/crypto/fileTransfer.ts under a real
// manifest. Encoders: the client's socket.io-parser, and for base64 either @krypt/shared (the
// app's byte helpers, `json-base64`) or the runtime's native Uint8Array.toBase64/fromBase64
// (`json-base64-native`, the best case). A variant that throws is recorded with its error.
//
// Usage: npm run e5:chunks [-- --quick] [--out results/<dir>]

import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { fromBase64, toBase64 } from '@krypt/shared';
import { chunkAad, chunkNonce, createManifest } from '../../frontend/src/crypto/fileManifest.ts';
import { encryptFileChunk, importFileKey } from '../../frontend/src/crypto/fileTransfer.ts';
import { FULL_CONFIG, QUICK_CONFIG, getSink, measure } from '../src/harness.ts';
import { toCsv } from '../src/csv.ts';

const ROOT = resolve(import.meta.dirname, '..');
// socket.io-parser is a dependency of the frontend's socket.io-client, not of evaluation/.
const { Encoder, Decoder } = createRequire(resolve(ROOT, '../frontend/package.json'))('socket.io-parser');

const { values: args } = parseArgs({ options: { quick: { type: 'boolean' }, out: { type: 'string' } } });
const cfg = { ...(args.quick ? QUICK_CONFIG : FULL_CONFIG), tinybench: false };
const SIZES = [256 * 1024, 1024 * 1024, 4 * 1024 * 1024];

type Wire = [string, ...Uint8Array[]];

/** The socket.io packet the client emits: event + ack id, like messaging.ts sendFileChunk. */
const packet = (frame: Record<string, unknown>) => ({ type: 2, nsp: '/', id: 7, data: ['file:chunk', frame] });

function decode(wire: Wire): { data: unknown[] } {
  let out: { data: unknown[] } | undefined;
  const d = new Decoder();
  d.on('decoded', (p: { data: unknown[] }) => (out = p));
  for (const part of wire) d.add(part);
  d.destroy();
  if (!out) throw new Error('decoder produced nothing');
  return out;
}

// Native base64 (ES2026; Node 25, Chromium 140+). Typed here because lib ES2023 lacks it.
const nativeB64 = {
  to: (b: Uint8Array) => (b as Uint8Array & { toBase64(): string }).toBase64(),
  from: (s: string) => (Uint8Array as unknown as { fromBase64(s: string): Uint8Array }).fromBase64(s),
};

const wireBytes = ([text, ...att]: Wire) => 1 + Buffer.byteLength(text) + att.reduce((n, b) => n + b.length, 0);

async function frameFor(size: number) {
  const m = createManifest('bench.bin', 'application/octet-stream', size, size);
  const plaintext = new Uint8Array(size).map((_, i) => i & 255);
  const data = await encryptFileChunk({
    fileKey: await importFileKey(m.fileKey),
    nonce: chunkNonce(m, 0),
    plaintext,
    aad: chunkAad(m, 'alice', 'bob', 0, 0),
  });
  return { to: 'bob', transferId: m.transferId, index: 0, nonceCounter: 0, data };
}

async function main() {
  const rows: Record<string, unknown>[] = [];
  for (const size of SIZES) {
    const frame = await frameFor(size);
    const enc = new Encoder();

    // Binary: the chunk rides as an attachment; the JSON holds a placeholder.
    const binWire = enc.encode(packet(frame)) as Wire;
    const binBack = decode(binWire).data[1] as { data: Uint8Array };
    if (Buffer.compare(Buffer.from(binBack.data), Buffer.from(frame.data)) !== 0) throw new Error('binary round trip');

    const binary = {
      encoding: 'binary',
      wire: binWire,
      // Sender: the small JSON header. Receiver: the header string; the attachment is used as received.
      copies: Buffer.byteLength(binWire[0]) * 2,
      encodeOp: () => enc.encode(packet(frame)),
      decodeOp: () => (decode(binWire).data[1] as { data: Uint8Array }).data,
    };

    // Base64: the chunk is a string field of the JSON packet.
    const base64 = (encoding: string, to: (b: Uint8Array) => string, from: (s: string) => Uint8Array) => {
      const b64 = to(frame.data);
      const wire = enc.encode(packet({ ...frame, data: b64 })) as Wire;
      if (wire.length !== 1) throw new Error('base64 packet should be text only');
      const decodeOp = () => from((decode(wire).data[1] as { data: string }).data);
      let error: string | undefined;
      try {
        if (Buffer.compare(Buffer.from(decodeOp()), Buffer.from(frame.data)) !== 0) throw new Error('base64 round trip');
      } catch (e) {
        error = (e as Error).message;
      }
      return {
        encoding,
        wire,
        error,
        // Sender: base64 string + packet string. Receiver: packet string + parsed base64 field + decoded bytes.
        copies: 2 * b64.length + 2 * Buffer.byteLength(wire[0]) + frame.data.length,
        encodeOp: () => enc.encode(packet({ ...frame, data: to(frame.data) })),
        decodeOp,
      };
    };

    const variants = [binary, base64('json-base64', toBase64, fromBase64), base64('json-base64-native', nativeB64.to, nativeB64.from)];
    for (const v of variants) {
      const error = 'error' in v ? v.error : undefined;
      const e = await measure(v.encodeOp, false, cfg);
      const d = error ? undefined : await measure(v.decodeOp, false, cfg);
      const row = {
        chunk_bytes: size,
        encoding: v.encoding,
        frame_payload_bytes: frame.data.length,
        wire_bytes_per_hop: wireBytes(v.wire),
        overhead_bytes_per_hop: wireBytes(v.wire) - frame.data.length,
        websocket_frames_per_hop: v.wire.length,
        encode_us_median: e.stats.median / 1e3,
        encode_us_p95: e.stats.p95 / 1e3,
        decode_us_median: d ? d.stats.median / 1e3 : null,
        decode_us_p95: d ? d.stats.p95 / 1e3 : null,
        encode_batches: e.stats.n,
        copy_bytes_per_frame: v.copies,
        error: error ?? '',
      };
      rows.push(row);
      console.log(
        `${String(size / 1024).padStart(5)} KiB ${v.encoding.padEnd(18)} wire ${String(row.wire_bytes_per_hop).padStart(8)} B` +
          `  encode ${row.encode_us_median.toFixed(1).padStart(8)} us  decode ${(row.decode_us_median?.toFixed(1) ?? 'FAILED').padStart(8)} us` +
          `  copies ${String(row.copy_bytes_per_frame).padStart(8)} B${error ? `  (${error})` : ''}`,
      );
    }
  }
  getSink();

  const today = new Date().toISOString().slice(0, 10);
  const outDir = resolve(ROOT, args.out ?? `results/files-${today}`);
  await mkdir(outDir, { recursive: true });
  await writeFile(resolve(outDir, 'e5-chunks.csv'), toCsv(rows, 6));
  await writeFile(
    resolve(outDir, 'e5-chunks.json'),
    JSON.stringify({ schema: 'krypt-e5-chunks/1', node: process.version, config: cfg, rows }, null, 1) + '\n',
  );
  console.log(`\n-> ${relative(ROOT, resolve(outDir, 'e5-chunks.csv'))}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
