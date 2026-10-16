// E5 (plan step 3.21): pure byte accounting, no timing.
//
// Bytes per handshake and per message, by component, for
//   v0       the deployed protocol (frontend/src/crypto/mlkem.ts, hooks/useChat.ts):
//            ML-KEM-1024 ct + ML-DSA-87 sig in a Socket.io JSON payload, base64 fields,
//            "GCM:" + base64(iv || ct || tag) message body
//   v1       Krypt-X3K (strategy 4.3) + KEM ratchet (4.4) with ML-KEM-768 ratchet keys
//   v1-xwing the same with X-Wing (ML-KEM-768 + X25519) ratchet keys (4.5)
// under three encodings:
//   raw          cryptographic material + fixed header integers only, no framing
//   binary       raw + a 4-byte length prefix per field and a 1-byte version tag
//                (the "every field length-prefixed" rule of 4.2)
//   json-base64  the actual Socket.io text frame: 42["private_message",{...}] with
//                base64 fields (what v0 sends today)
// Plaintext bytes are tracked separately so "overhead" = total - plaintext.
// Sizes are FIPS 203/204 constants and checked against the libraries at runtime.

import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { parseArgs } from 'node:util';

const ROOT = resolve(import.meta.dirname, '..');
const { values: args } = parseArgs({
  options: { out: { type: 'string' }, plaintext: { type: 'string', default: '100' } },
});
const P = Number(args.plaintext); // plaintext bytes of a typical chat message

// --- sizes, verified against the implementations ---------------------------
const S = (() => {
  const k1024 = ml_kem1024.keygen();
  const k768 = ml_kem768.keygen();
  const xw = ml_kem768_x25519.keygen();
  const d87 = ml_dsa87.keygen();
  return {
    kem1024: { ek: k1024.publicKey.length, ct: ml_kem1024.encapsulate(k1024.publicKey).cipherText.length },
    kem768: { ek: k768.publicKey.length, ct: ml_kem768.encapsulate(k768.publicKey).cipherText.length },
    xwing: { ek: xw.publicKey.length, ct: ml_kem768_x25519.encapsulate(xw.publicKey).cipherText.length },
    dsa87: { pk: d87.publicKey.length, sig: ml_dsa87.sign(new Uint8Array(32), d87.secretKey).length },
    iv: 12,
    tag: 16,
    sessionId: 32,
  };
})();
const FIPS = { kem1024: [1568, 1568], kem768: [1184, 1088], dsa87: [2592, 4627] };
if (S.kem1024.ek !== FIPS.kem1024[0] || S.kem1024.ct !== FIPS.kem1024[1] || S.kem768.ek !== FIPS.kem768[0] || S.kem768.ct !== FIPS.kem768[1] || S.dsa87.pk !== FIPS.dsa87[0] || S.dsa87.sig !== FIPS.dsa87[1])
  throw new Error('library sizes disagree with FIPS 203/204');

// --- model -------------------------------------------------------------------
// A message is a list of fields. Each field has a component (for the stacked
// bar), a raw byte length, and how it is carried in JSON (base64 / string / number).
type Kind = 'bin' | 'str' | 'num';
interface Field { key: string; component: string; bytes: number; kind: Kind; value?: string | number; group?: string }

const b64len = (n: number) => 4 * Math.ceil(n / 3);
const fakeB64 = (n: number) => 'A'.repeat(b64len(n));

const ROUTE: Field[] = [
  { key: 'to', component: 'routing', bytes: 3, kind: 'str', value: 'bob' },
  { key: 'from', component: 'routing', bytes: 5, kind: 'str', value: 'alice' },
  { key: 'type', component: 'routing', bytes: 4, kind: 'str', value: 'text' },
];

interface Scenario { version: string; phase: 'bundle' | 'first-message' | 'steady-message'; note: string; fields: Field[]; plaintext: number; jsonBuilder: (f: Field[]) => unknown }

function v0(): Scenario[] {
  // Bundle: request_public_key ack carries exportPublicIdentity() JSON as a string.
  const bundle: Field[] = [
    { key: 'kem', component: 'KEM public key', bytes: S.kem1024.ek, kind: 'bin' },
    { key: 'dsa', component: 'signature public key', bytes: S.dsa87.pk, kind: 'bin' },
  ];
  const body = (withHs: boolean): Field[] => [
    ...ROUTE,
    { key: 'ciphertext', component: 'AEAD (iv+tag)', bytes: S.iv + S.tag, kind: 'bin', group: 'ct' },
    ...(withHs
      ? [
          { key: 'eph', component: 'KEM ciphertext', bytes: S.kem1024.ct, kind: 'bin' as Kind },
          { key: 'sig', component: 'signature', bytes: S.dsa87.sig, kind: 'bin' as Kind },
        ]
      : []),
  ];
  const v0Json = (fs: Field[]) => {
    const o: Record<string, unknown> = {};
    for (const f of fs) {
      if (f.key === 'ciphertext') o.ciphertext = 'GCM:' + fakeB64(S.iv + P + S.tag);
      else o[f.key] = f.kind === 'bin' ? fakeB64(f.bytes) : f.value;
    }
    return o;
  };
  const bundleJson = (fs: Field[]) =>
    JSON.stringify({ version: 'ML-KEM-1024/ML-DSA-87 (NIST FIPS 203/204)', ...Object.fromEntries(fs.map((f) => [f.key, fakeB64(f.bytes)])) });
  return [
    { version: 'v0', phase: 'bundle', note: 'ack of request_public_key: identity JSON string', fields: bundle, plaintext: 0, jsonBuilder: bundleJson },
    { version: 'v0', phase: 'first-message', note: 'private_message with eph (KEM ct) + sig', fields: body(true), plaintext: P, jsonBuilder: v0Json },
    { version: 'v0', phase: 'steady-message', note: 'private_message, hash-ratchet key, no PQ material', fields: body(false), plaintext: P, jsonBuilder: v0Json },
  ];
}

function v1(kemName: 'kem768' | 'xwing'): Scenario[] {
  const version = kemName === 'kem768' ? 'v1' : 'v1-xwing';
  const r = S[kemName];
  const header: Field[] = [
    { key: 'v', component: 'header fields', bytes: 1, kind: 'num', value: 1, group: 'h' },
    { key: 'sid', component: 'header fields', bytes: S.sessionId, kind: 'bin', group: 'h' },
    { key: 'e', component: 'header fields', bytes: 4, kind: 'num', value: 3, group: 'h' },
    { key: 'n', component: 'header fields', bytes: 4, kind: 'num', value: 17, group: 'h' },
    { key: 'pn', component: 'header fields', bytes: 4, kind: 'num', value: 12, group: 'h' },
  ];
  const aead: Field = { key: 'c', component: 'AEAD (iv+tag)', bytes: S.tag, kind: 'bin', group: 'ct' }; // IV is derived (4.4)
  const bundle: Field[] = [
    { key: 'ik', component: 'signature public key', bytes: S.dsa87.pk, kind: 'bin' },
    { key: 'spkId', component: 'header fields', bytes: 4, kind: 'num', value: 7 },
    { key: 'spk', component: 'KEM public key', bytes: S.kem1024.ek, kind: 'bin' },
    { key: 'spkSig', component: 'signature', bytes: S.dsa87.sig, kind: 'bin' },
    { key: 'opkId', component: 'header fields', bytes: 4, kind: 'num', value: 4242 },
    { key: 'opk', component: 'KEM public key', bytes: S.kem1024.ek, kind: 'bin' },
    { key: 'opkSig', component: 'signature', bytes: S.dsa87.sig, kind: 'bin' },
  ];
  const init: Field[] = [
    { key: 'ct1', component: 'KEM ciphertext', bytes: S.kem1024.ct, kind: 'bin', group: 'init' },
    { key: 'ct2', component: 'KEM ciphertext', bytes: S.kem1024.ct, kind: 'bin', group: 'init' },
    { key: 'ek', component: 'KEM public key', bytes: r.ek, kind: 'bin', group: 'init' },
    { key: 'sig', component: 'signature', bytes: S.dsa87.sig, kind: 'bin', group: 'init' },
  ];
  const ratchet: Field[] = [
    { key: 'ct', component: 'KEM ciphertext', bytes: r.ct, kind: 'bin', group: 'h' },
    { key: 'ek', component: 'KEM public key', bytes: r.ek, kind: 'bin', group: 'h' },
  ];
  const json = (fs: Field[]) => {
    const o: Record<string, unknown> = {};
    for (const f of fs) {
      const val = f.key === 'c' ? fakeB64(P + S.tag) : f.kind === 'bin' ? fakeB64(f.bytes) : f.value;
      if (f.group && f.group !== 'ct') ((o[f.group] ??= {}) as Record<string, unknown>)[f.key] = val;
      else o[f.key] = val;
    }
    return o;
  };
  const bundleJson = (fs: Field[]) => JSON.stringify(json(fs));
  return [
    { version, phase: 'bundle', note: 'GET /bundle/:user: IK, SPK+sig, one OPK+sig', fields: bundle, plaintext: 0, jsonBuilder: bundleJson },
    { version, phase: 'first-message', note: 'epoch-0 message with init header {ct1, ct2, ek_A1, sig_A}', fields: [...ROUTE, ...header, ...init, aead], plaintext: P, jsonBuilder: json },
    { version, phase: 'steady-message', note: 'K=1: every header repeats (ct, ek)', fields: [...ROUTE, ...header, ...ratchet, aead], plaintext: P, jsonBuilder: json },
  ];
}

// --- encodings ---------------------------------------------------------------
interface Row { version: string; phase: string; encoding: string; component: string; bytes: number }

function account(sc: Scenario): Row[] {
  const rows: Row[] = [];
  const base = { version: sc.version, phase: sc.phase };
  const byComp = (fn: (f: Field) => number) => {
    const m = new Map<string, number>();
    for (const f of sc.fields) m.set(f.component, (m.get(f.component) ?? 0) + fn(f));
    return m;
  };
  const push = (encoding: string, m: Map<string, number>) => {
    for (const [component, bytes] of m) rows.push({ ...base, encoding, component, bytes });
    if (sc.plaintext) rows.push({ ...base, encoding, component: 'plaintext', bytes: sc.plaintext });
  };
  // raw
  push('raw', byComp((f) => f.bytes));
  // binary frame: version byte + 4-byte length prefix per field (+ plaintext field's prefix inside AEAD field)
  const bin = byComp((f) => f.bytes);
  bin.set('framing', 1 + 4 * sc.fields.length);
  push('binary', bin);
  // json-base64: real string length of the Socket.io text frame
  const isBundle = sc.phase === 'bundle';
  const built = sc.jsonBuilder(sc.fields);
  const payload = isBundle ? (built as string) : JSON.stringify(built);
  // bundle is returned as a Socket.io ack: 43<id>[<json string>]
  const frame = isBundle ? `431[${JSON.stringify(payload)}]` : `42["private_message",${payload}]`;
  const total = new TextEncoder().encode(frame).length;
  const js = byComp((f) => {
    if (f.key === 'ciphertext') return 'GCM:'.length + b64len(S.iv + P + S.tag) - P; // AEAD share; plaintext counted below
    if (f.key === 'c') return b64len(P + S.tag) - P;
    if (f.kind === 'bin') return b64len(f.bytes);
    return 0; // strings/numbers: counted in framing below
  });
  let accounted = sc.plaintext;
  for (const v of js.values()) accounted += v;
  js.set('framing', total - accounted);
  push('json-base64', js);
  return rows;
}

async function main() {
  const scenarios = [...v0(), ...v1('kem768'), ...v1('xwing')];
  const rows = scenarios.flatMap(account);
  const today = new Date().toISOString().slice(0, 10);
  const outDir = resolve(ROOT, args.out ?? `results/${today}`);
  await mkdir(outDir, { recursive: true });

  const csv = ['version,phase,encoding,component,bytes', ...rows.map((r) => `${r.version},${r.phase},${r.encoding},${r.component},${r.bytes}`)].join('\n');
  await writeFile(resolve(outDir, 'e5-bytes.csv'), csv + '\n');
  await writeFile(
    resolve(outDir, 'e5-bytes.json'),
    JSON.stringify({ schema: 'krypt-e5/1', plaintextBytes: P, sizes: S, scenarios: scenarios.map(({ jsonBuilder: _j, ...s }) => s), rows }, null, 1),
  );

  // Console summary: totals and overhead per (version, phase, encoding), plus handshake = bundle + first message.
  const totals = new Map<string, { total: number; pt: number }>();
  for (const r of rows) {
    const k = `${r.version}|${r.phase}|${r.encoding}`;
    const t = totals.get(k) ?? { total: 0, pt: 0 };
    t.total += r.bytes;
    if (r.component === 'plaintext') t.pt += r.bytes;
    totals.set(k, t);
  }
  console.log(`E5 byte accounting (plaintext = ${P} B)\n`);
  console.log('version   phase            raw    binary  json-base64   (overhead = total - plaintext)');
  for (const version of ['v0', 'v1', 'v1-xwing'])
    for (const phase of ['bundle', 'first-message', 'steady-message', 'handshake']) {
      const get = (enc: string) => {
        if (phase === 'handshake') {
          const a = totals.get(`${version}|bundle|${enc}`)!;
          const b = totals.get(`${version}|first-message|${enc}`)!;
          return a.total + b.total - a.pt - b.pt;
        }
        const t = totals.get(`${version}|${phase}|${enc}`)!;
        return t.total - t.pt;
      };
      console.log(`${version.padEnd(9)} ${phase.padEnd(15)} ${String(get('raw')).padStart(6)} ${String(get('binary')).padStart(8)} ${String(get('json-base64')).padStart(11)}`);
    }
  console.log(`\n-> ${relative(ROOT, resolve(outDir, 'e5-bytes.csv'))}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
