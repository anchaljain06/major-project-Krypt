// E5 (plan step 3.21): pure byte accounting, no timing.
//
// Bytes per handshake and per message, by component, for
//   v0           the protocol-v0 baseline (tag protocol-v0: mlkem.ts + hooks/useChat.ts):
//                ML-KEM-1024 ct + ML-DSA-87 sig in a Socket.io JSON payload, base64 fields,
//                "GCM:" + base64(iv || ct || tag) message body. Hand-modelled: that code is gone.
//   v1           measured, not modelled: a real Krypt-X3K handshake and K = 1 ratchet through
//                the shipped SessionManager (frontend/src/crypto), ML-KEM-1024 ratchet keys
//   v1-mlkem768  comparison only: the same real v1 envelopes with the ratchet ek/ct and the
//   v1-xwing     suite name resized to ML-KEM-768 / X-Wing (spec 2.1 says why v1 ships 1024)
// under three encodings:
//   raw          cryptographic material + header fields only, no framing
//   binary       v0: raw + a 4-byte length prefix per field and a 1-byte version tag;
//                v1: the real binary envelope (encodeBinaryEnvelope, spec 8.3)
//   json-base64  the Socket.io text frame 42["private_message",{...}]. v1 uses the real
//                buildWirePayload() object; the v1 bundle is the real GET /bundle JSON body
// Plaintext bytes are tracked separately so "overhead" = total - plaintext.

import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { parseArgs } from 'node:util';
import { world } from '../../frontend/test/helpers.ts';
import { buildWirePayload } from '../../frontend/src/crypto/appMessage.ts';
import { encodeBinaryEnvelope, parseEnvelope, type EnvelopeV1, type Header } from '../../frontend/src/crypto/envelope.ts';
import type { PrekeyBundleWire } from '../../frontend/src/crypto/prekeys.ts';

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
  };
})();
const FIPS = { kem1024: [1568, 1568], kem768: [1184, 1088], dsa87: [2592, 4627] };
if (S.kem1024.ek !== FIPS.kem1024[0] || S.kem1024.ct !== FIPS.kem1024[1] || S.kem768.ek !== FIPS.kem768[0] || S.kem768.ct !== FIPS.kem768[1] || S.dsa87.pk !== FIPS.dsa87[0] || S.dsa87.sig !== FIPS.dsa87[1])
  throw new Error('library sizes disagree with FIPS 203/204');

interface Row { version: string; phase: string; encoding: string; component: string; bytes: number }
const sum = (m: Record<string, number>) => Object.values(m).reduce((a, b) => a + b, 0);

// --- v0: hand-modelled (the code only exists at tag protocol-v0) --------------
// A message is a list of fields. Each field has a component (for the stacked
// bar), a raw byte length, and how it is carried in JSON (base64 / string).
interface Field { key: string; component: string; bytes: number; kind: 'bin' | 'str'; value?: string }

const b64len = (n: number) => 4 * Math.ceil(n / 3);
const fakeB64 = (n: number) => 'A'.repeat(b64len(n));

const ROUTE: Field[] = [
  { key: 'to', component: 'routing', bytes: 3, kind: 'str', value: 'bob' },
  { key: 'from', component: 'routing', bytes: 5, kind: 'str', value: 'alice' },
  { key: 'type', component: 'routing', bytes: 4, kind: 'str', value: 'text' },
];

interface Scenario { phase: 'bundle' | 'first-message' | 'steady-message'; fields: Field[]; plaintext: number; frame: (f: Field[]) => string }

function v0(): Scenario[] {
  // Bundle: request_public_key ack carries exportPublicIdentity() JSON as a string.
  const bundle: Field[] = [
    { key: 'kem', component: 'KEM public key', bytes: S.kem1024.ek, kind: 'bin' },
    { key: 'dsa', component: 'signature public key', bytes: S.dsa87.pk, kind: 'bin' },
  ];
  const body = (withHs: boolean): Field[] => [
    ...ROUTE,
    { key: 'ciphertext', component: 'AEAD (iv+tag)', bytes: S.iv + S.tag, kind: 'bin' },
    ...(withHs
      ? [
          { key: 'eph', component: 'KEM ciphertext', bytes: S.kem1024.ct, kind: 'bin' as const },
          { key: 'sig', component: 'signature', bytes: S.dsa87.sig, kind: 'bin' as const },
        ]
      : []),
  ];
  const message = (fs: Field[]) => {
    const o: Record<string, unknown> = {};
    for (const f of fs) {
      if (f.key === 'ciphertext') o.ciphertext = 'GCM:' + fakeB64(S.iv + P + S.tag);
      else o[f.key] = f.kind === 'bin' ? fakeB64(f.bytes) : f.value;
    }
    return `42["private_message",${JSON.stringify(o)}]`;
  };
  // The bundle is returned as a Socket.io ack: 43<id>[<json string>]
  const bundleFrame = (fs: Field[]) =>
    `431[${JSON.stringify(JSON.stringify({ version: 'ML-KEM-1024/ML-DSA-87 (NIST FIPS 203/204)', ...Object.fromEntries(fs.map((f) => [f.key, fakeB64(f.bytes)])) }))}]`;
  return [
    { phase: 'bundle', fields: bundle, plaintext: 0, frame: bundleFrame },
    { phase: 'first-message', fields: body(true), plaintext: P, frame: message },
    { phase: 'steady-message', fields: body(false), plaintext: P, frame: message },
  ];
}

function v0Rows(sc: Scenario): Row[] {
  const rows: Row[] = [];
  const base = { version: 'v0', phase: sc.phase };
  const byComp = (fn: (f: Field) => number) => {
    const m: Record<string, number> = {};
    for (const f of sc.fields) m[f.component] = (m[f.component] ?? 0) + fn(f);
    return m;
  };
  const push = (encoding: string, m: Record<string, number>) => {
    for (const [component, bytes] of Object.entries(m)) rows.push({ ...base, encoding, component, bytes });
    if (sc.plaintext) rows.push({ ...base, encoding, component: 'plaintext', bytes: sc.plaintext });
  };
  push('raw', byComp((f) => f.bytes));
  // binary frame: version byte + 4-byte length prefix per field
  push('binary', { ...byComp((f) => f.bytes), framing: 1 + 4 * sc.fields.length });
  // json-base64: real string length of the Socket.io text frame
  const total = Buffer.byteLength(sc.frame(sc.fields));
  const js = byComp((f) => {
    if (f.key === 'ciphertext') return 'GCM:'.length + b64len(S.iv + P + S.tag) - P; // AEAD share; plaintext counted below
    if (f.kind === 'bin') return b64len(f.bytes);
    return 0; // strings: counted in framing below
  });
  push('json-base64', { ...js, framing: total - sum(js) - sc.plaintext });
  return rows;
}

// --- v1: measured from the shipped code ----------------------------------------
// One real conversation: Alice fetches Bob's bundle, sends the epoch-0 message (init header),
// Bob replies, Alice sends again. At K = 1 that last header carries (ct, ek): the steady state.
interface V1Sample { bundle: PrekeyBundleWire; first: EnvelopeV1; steady: EnvelopeV1 }

async function sampleV1(): Promise<V1Sample> {
  const { dir, alice, bob } = await world({ suite: 'mlkem1024', ratchetEveryK: 1 });
  const pt = () => new Uint8Array(P).fill(0x61);
  const bundle = await dir.fetchBundle('bob'); // the GET /bundle body Alice receives
  const first = await alice.sm.encrypt('bob', pt(), 'text');
  await bob.sm.decrypt(first);
  await alice.sm.decrypt(await bob.sm.encrypt('alice', pt(), 'text'));
  const steady = await alice.sm.encrypt('bob', pt(), 'text');
  if (!first.init || !steady.kem) throw new Error('E5: expected an init header and a K = 1 ratchet header');
  return { bundle, first, steady };
}

/** A ratchet suite: the real envelope with its ratchet ek/ct and suite name resized. */
interface Variant { version: string; suite: string; ek: number; ct: number }
const VARIANTS: Variant[] = [
  { version: 'v1', suite: 'mlkem1024', ...S.kem1024 },
  { version: 'v1-mlkem768', suite: 'mlkem768', ...S.kem768 },
  { version: 'v1-xwing', suite: 'xwing', ...S.xwing },
];

function resize(env: EnvelopeV1, v: Variant): { header: Header; body: Uint8Array; wire: EnvelopeV1 } {
  const { header, body } = parseEnvelope(env);
  if (v.suite === env.suite) return { header, body, wire: env };
  const zeros = (n: number) => new Uint8Array(n);
  const b64u = (n: number) => Buffer.from(zeros(n)).toString('base64url');
  const h: Header = { ...header, suite: v.suite as Header['suite'] };
  const wire: EnvelopeV1 = { ...env, suite: v.suite as EnvelopeV1['suite'] };
  if (header.kem) {
    h.kem = { ct: zeros(v.ct), ek: zeros(v.ek) };
    wire.kem = { ct: b64u(v.ct), ek: b64u(v.ek) };
  }
  if (header.init && env.init) {
    h.init = { ...header.init, ek: zeros(v.ek) };
    wire.init = { ...env.init, ek: b64u(v.ek) };
  }
  return { header: h, body, wire };
}

function v1Rows(sample: V1Sample, v: Variant): Row[] {
  const rows: Row[] = [];
  const add = (phase: string, encoding: string, m: Record<string, number>) => {
    for (const [component, bytes] of Object.entries(m)) if (bytes) rows.push({ version: v.version, phase, encoding, component, bytes });
  };
  const raw = (s: string) => Buffer.from(s, 'base64url').length; // also decodes standard base64

  // Bundle (the same for every ratchet suite): identity JSON (ML-DSA key plus a KEM key that
  // v1 does not use), the signed prekey and one one-time prekey, each with its signature.
  const ik = JSON.parse(sample.bundle.identityKey) as { kem: string; dsa: string };
  const pks = [sample.bundle.signedPrekey!, sample.bundle.oneTimePrekey!];
  const bundleRaw = {
    'signature public key': raw(ik.dsa),
    'KEM public key': raw(ik.kem) + pks.reduce((t, k) => t + raw(k.publicKey), 0),
    signature: pks.reduce((t, k) => t + raw(k.signature), 0),
    'header fields': 4 * pks.length + sample.bundle.username.length,
  };
  add('bundle', 'raw', bundleRaw);
  add('bundle', 'binary', bundleRaw); // v1 has no binary bundle format; shown as raw
  const bundleB64 = {
    'signature public key': ik.dsa.length,
    'KEM public key': ik.kem.length + pks.reduce((t, k) => t + k.publicKey.length, 0),
    signature: pks.reduce((t, k) => t + k.signature.length, 0),
  };
  add('bundle', 'json-base64', { ...bundleB64, framing: Buffer.byteLength(JSON.stringify(sample.bundle)) - sum(bundleB64) });

  for (const [phase, env] of [['first-message', sample.first], ['steady-message', sample.steady]] as const) {
    const { header, body, wire } = resize(env, v);
    const init = header.init;
    const kemCt = header.kem ? header.kem.ct.length : init ? init.ct1.length + (init.ct2?.length ?? 0) : 0;
    const kemEk = header.kem?.ek.length ?? init?.ek.length ?? 0;
    const sig = init?.sig.length ?? 0;
    const tag = body.length - P;
    // Header fields: everything in the canonical header except crypto material and length prefixes.
    const fields = 4 + header.suite.length + header.sessionId.length + header.from.length + header.to.length +
      header.contentType.length + 12 + (init ? 4 + (init.opkId === null ? 0 : 4) : 0);
    const material = { 'KEM ciphertext': kemCt, 'KEM public key': kemEk, signature: sig, 'AEAD (iv+tag)': tag, 'header fields': fields };
    const payload = buildWirePayload(wire);
    add(phase, 'raw', { ...material, routing: payload.to.length + payload.type.length, plaintext: P });
    const bin = encodeBinaryEnvelope({ header, body }).length;
    add(phase, 'binary', { ...material, framing: bin - sum(material) - P, plaintext: P });
    const frame = Buffer.byteLength(`42["private_message",${JSON.stringify(payload)}]`);
    const js = {
      'KEM ciphertext': wire.kem ? wire.kem.ct.length : wire.init ? wire.init.ct1.length + (wire.init.ct2?.length ?? 0) : 0,
      'KEM public key': wire.kem?.ek.length ?? wire.init?.ek.length ?? 0,
      signature: wire.init?.sig.length ?? 0,
      'AEAD (iv+tag)': wire.body.length - Math.ceil((P * 4) / 3),
    };
    add(phase, 'json-base64', { ...js, framing: frame - sum(js) - P, plaintext: P });
  }
  return rows;
}

async function main() {
  const sample = await sampleV1();
  const rows = [...v0().flatMap(v0Rows), ...VARIANTS.flatMap((v) => v1Rows(sample, v))];
  const versions = ['v0', ...VARIANTS.map((v) => v.version)];
  const today = new Date().toISOString().slice(0, 10);
  const outDir = resolve(ROOT, args.out ?? `results/${today}`);
  await mkdir(outDir, { recursive: true });

  const csv = ['version,phase,encoding,component,bytes', ...rows.map((r) => `${r.version},${r.phase},${r.encoding},${r.component},${r.bytes}`)].join('\n');
  await writeFile(resolve(outDir, 'e5-bytes.csv'), csv + '\n');
  await writeFile(
    resolve(outDir, 'e5-bytes.json'),
    JSON.stringify({ schema: 'krypt-e5/2', plaintextBytes: P, sizes: S, versions, rows }, null, 1),
  );

  // Console summary: overhead per (version, phase, encoding), plus handshake = bundle + first message.
  const totals = new Map<string, { total: number; pt: number }>();
  for (const r of rows) {
    const k = `${r.version}|${r.phase}|${r.encoding}`;
    const t = totals.get(k) ?? { total: 0, pt: 0 };
    t.total += r.bytes;
    if (r.component === 'plaintext') t.pt += r.bytes;
    totals.set(k, t);
  }
  const over = (version: string, phase: string, enc: string) => {
    const t = totals.get(`${version}|${phase}|${enc}`)!;
    return t.total - t.pt;
  };
  console.log(`E5 byte accounting (plaintext = ${P} B; overhead = total - plaintext)\n`);
  console.log('version       phase              raw   binary  json-base64');
  for (const version of versions)
    for (const phase of ['bundle', 'first-message', 'steady-message', 'handshake']) {
      const get = (enc: string) => (phase === 'handshake' ? over(version, 'bundle', enc) + over(version, 'first-message', enc) : over(version, phase, enc));
      console.log(`${version.padEnd(13)} ${phase.padEnd(15)} ${String(get('raw')).padStart(6)} ${String(get('binary')).padStart(8)} ${String(get('json-base64')).padStart(12)}`);
    }
  console.log(`\n-> ${relative(ROOT, resolve(outDir, 'e5-bytes.csv'))}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
