// Experiment definitions E1-E4 (strategy section 6.1). Shared by the browser
// worker/main-thread page and the Node runner, so both measure the same thing.
//
// Each op has a `setup` that builds inputs, performs a one-off correctness
// self-check (decaps == encaps secret, verify == true), and returns the
// function to time. A setup that throws `Unsupported` is recorded as
// status 'unsupported' instead of failing the run.

import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { measure, type BenchConfig, type Measurement, type OpFn } from './harness.ts';

export type Exp = 'E1' | 'E2' | 'E3' | 'E4';
export type Backend = 'noble' | 'liboqs-wasm' | 'webcrypto-native' | 'node-crypto';

export interface OpSpec {
  exp: Exp;
  family: string; // ML-KEM, X-Wing, ML-DSA, X25519, Ed25519, AES-256-GCM, KDF
  alg: string; // ML-KEM-768, AES-256-GCM, ...
  op: string; // keygen, encaps, decaps, sign, verify, derive, encrypt, decrypt, chain-step, ...
  backend: Backend;
  async: boolean;
  bytes?: number; // payload size for throughput ops
  setup: () => Promise<OpFn>;
}

export interface OpResult {
  id: string;
  exp: Exp;
  family: string;
  alg: string;
  op: string;
  backend: Backend;
  status: 'ok' | 'unsupported' | 'error';
  reason?: string;
  bytes?: number;
  /** Throughput derived from the median, MB/s (1 MB = 1e6 B). Only for sized ops. */
  mbpsMedian?: number;
  measurement?: Measurement;
}

export class Unsupported extends Error {}

export const opId = (o: Pick<OpSpec, 'exp' | 'alg' | 'op' | 'backend'> & { bytes?: number }) =>
  `${o.exp}/${o.alg}/${o.op}${o.bytes !== undefined ? `@${o.bytes}` : ''}/${o.backend}`;

const enc = new TextEncoder();
const MSG = enc.encode('Krypt-init benchmark transcript hash placeholder 0123456789abcdef'); // 64 B
type Bytes = Uint8Array<ArrayBuffer>;
const u8 = (x: ArrayBuffer | Uint8Array): Uint8Array => (x instanceof Uint8Array ? x : new Uint8Array(x));
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function check(cond: boolean, what: string) {
  if (!cond) throw new Error(`self-check failed: ${what}`);
}
function rand(n: number): Bytes {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
}
const subtle = () => {
  if (!globalThis.crypto?.subtle) throw new Unsupported('crypto.subtle unavailable (insecure context?)');
  return globalThis.crypto.subtle;
};

// ---------------------------------------------------------------------------
// Native WebCrypto feature detection (WICG "Modern Algorithms in WebCrypto").
// The draft adds a static SubtleCrypto.supports(op, alg[, lengthOrAlg]) and the
// encapsulateBits/decapsulateBits methods. We record what supports() says AND
// whether a real call works, because early implementations may disagree.
// ---------------------------------------------------------------------------
export interface NativeSupport {
  supportsFn: boolean;
  probes: Record<string, boolean | string>;
}

export function detectNativeSupport(): NativeSupport {
  const SC = (globalThis as { SubtleCrypto?: { supports?: (op: string, alg: unknown) => boolean } }).SubtleCrypto;
  const supportsFn = typeof SC?.supports === 'function';
  const probes: Record<string, boolean | string> = {};
  const pairs: [string, string][] = [
    ['generateKey', 'ML-KEM-512'],
    ['generateKey', 'ML-KEM-768'],
    ['generateKey', 'ML-KEM-1024'],
    ['encapsulateBits', 'ML-KEM-768'],
    ['decapsulateBits', 'ML-KEM-768'],
    ['encapsulateKey', 'ML-KEM-768'],
    ['generateKey', 'ML-DSA-44'],
    ['generateKey', 'ML-DSA-65'],
    ['generateKey', 'ML-DSA-87'],
    ['sign', 'ML-DSA-65'],
    ['generateKey', 'X25519'],
    ['deriveBits', 'X25519'],
    ['generateKey', 'Ed25519'],
    ['sign', 'Ed25519'],
  ];
  for (const [op, alg] of pairs) {
    const key = `${op}:${alg}`;
    if (!supportsFn) {
      probes[key] = 'no SubtleCrypto.supports';
      continue;
    }
    try {
      probes[key] = !!SC!.supports!(op, { name: alg });
    } catch (e) {
      probes[key] = `throws: ${(e as Error).message}`;
    }
  }
  probes['subtle.encapsulateBits'] = typeof (globalThis.crypto?.subtle as unknown as Record<string, unknown>)?.encapsulateBits === 'function';
  return { supportsFn, probes };
}

type AnySubtle = SubtleCrypto & {
  encapsulateBits(alg: AlgorithmIdentifier, key: CryptoKey): Promise<{ sharedKey: ArrayBuffer; ciphertext: ArrayBuffer }>;
  decapsulateBits(alg: AlgorithmIdentifier, key: CryptoKey, ct: BufferSource): Promise<ArrayBuffer>;
};

async function nativeGen(name: string, usages: string[]): Promise<CryptoKeyPair> {
  const s = subtle() as AnySubtle;
  if (name.startsWith('ML-KEM') && typeof s.encapsulateBits !== 'function')
    throw new Unsupported('subtle.encapsulateBits not implemented');
  try {
    return (await s.generateKey({ name }, true, usages as KeyUsage[])) as CryptoKeyPair;
  } catch (e) {
    throw new Unsupported(`generateKey(${name}) -> ${(e as Error).name}: ${(e as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// liboqs-js (WASM). Loaded lazily so a broken build only marks its rows unsupported.
// ---------------------------------------------------------------------------
type OqsKem = {
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(pk: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(ct: Uint8Array, sk: Uint8Array): Uint8Array;
};
type OqsSig = {
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array };
  sign(msg: Uint8Array, sk: Uint8Array): Uint8Array;
  verify(msg: Uint8Array, sig: Uint8Array, pk: Uint8Array): boolean;
};
const oqsCache = new Map<string, Promise<unknown>>();
function oqs<T>(alg: string): Promise<T> {
  if (!oqsCache.has(alg)) {
    oqsCache.set(
      alg,
      (async () => {
        // Destructured dynamic imports let Rollup tree-shake the other ~100
        // liboqs algorithms out of the browser bundle (see vite.config.ts).
        try {
          switch (alg) {
            case 'ML-KEM-512': { const { createMLKEM512 } = await import('@oqs/liboqs-js/kem'); return await createMLKEM512(); }
            case 'ML-KEM-768': { const { createMLKEM768 } = await import('@oqs/liboqs-js/kem'); return await createMLKEM768(); }
            case 'ML-KEM-1024': { const { createMLKEM1024 } = await import('@oqs/liboqs-js/kem'); return await createMLKEM1024(); }
            case 'ML-DSA-44': { const { createMLDSA44 } = await import('@oqs/liboqs-js/sig'); return await createMLDSA44(); }
            case 'ML-DSA-65': { const { createMLDSA65 } = await import('@oqs/liboqs-js/sig'); return await createMLDSA65(); }
            case 'ML-DSA-87': { const { createMLDSA87 } = await import('@oqs/liboqs-js/sig'); return await createMLDSA87(); }
          }
          throw new Error(`unknown alg ${alg}`);
        } catch (e) {
          throw new Unsupported(`liboqs-js load failed: ${(e as Error).message}`);
        }
      })(),
    );
  }
  return oqsCache.get(alg) as Promise<T>;
}

// ---------------------------------------------------------------------------
// E1: ML-KEM and X-Wing
// ---------------------------------------------------------------------------
const NOBLE_KEM = { 'ML-KEM-512': ml_kem512, 'ML-KEM-768': ml_kem768, 'ML-KEM-1024': ml_kem1024 } as const;
const NOBLE_DSA = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 } as const;

function kemOps(alg: keyof typeof NOBLE_KEM): OpSpec[] {
  const base = { exp: 'E1' as const, family: 'ML-KEM', alg };
  const noble = NOBLE_KEM[alg];
  const ops: OpSpec[] = [
    { ...base, op: 'keygen', backend: 'noble', async: false, setup: async () => () => noble.keygen() },
    {
      ...base, op: 'encaps', backend: 'noble', async: false,
      setup: async () => {
        const { publicKey } = noble.keygen();
        return () => noble.encapsulate(publicKey);
      },
    },
    {
      ...base, op: 'decaps', backend: 'noble', async: false,
      setup: async () => {
        const { publicKey, secretKey } = noble.keygen();
        const { cipherText, sharedSecret } = noble.encapsulate(publicKey);
        check(eq(noble.decapsulate(cipherText, secretKey), sharedSecret), `${alg} noble decaps`);
        return () => noble.decapsulate(cipherText, secretKey);
      },
    },
    {
      ...base, op: 'keygen', backend: 'liboqs-wasm', async: false,
      setup: async () => {
        const k = await oqs<OqsKem>(alg);
        return () => k.generateKeyPair();
      },
    },
    {
      ...base, op: 'encaps', backend: 'liboqs-wasm', async: false,
      setup: async () => {
        const k = await oqs<OqsKem>(alg);
        const { publicKey } = k.generateKeyPair();
        return () => k.encapsulate(publicKey);
      },
    },
    {
      ...base, op: 'decaps', backend: 'liboqs-wasm', async: false,
      setup: async () => {
        const k = await oqs<OqsKem>(alg);
        const { publicKey, secretKey } = k.generateKeyPair();
        const { ciphertext, sharedSecret } = k.encapsulate(publicKey);
        check(eq(k.decapsulate(ciphertext, secretKey), sharedSecret), `${alg} liboqs decaps`);
        // Cross-implementation check: noble must decapsulate liboqs ciphertexts.
        check(eq(noble.decapsulate(ciphertext, secretKey), sharedSecret), `${alg} noble<->liboqs interop`);
        return () => k.decapsulate(ciphertext, secretKey);
      },
    },
    {
      ...base, op: 'keygen', backend: 'webcrypto-native', async: true,
      setup: async () => {
        await nativeGen(alg, ['encapsulateBits', 'decapsulateBits']);
        return () => subtle().generateKey({ name: alg }, true, ['encapsulateBits', 'decapsulateBits'] as unknown as KeyUsage[]);
      },
    },
    {
      ...base, op: 'encaps', backend: 'webcrypto-native', async: true,
      setup: async () => {
        const kp = await nativeGen(alg, ['encapsulateBits', 'decapsulateBits']);
        const s = subtle() as AnySubtle;
        return () => s.encapsulateBits({ name: alg }, kp.publicKey);
      },
    },
    {
      ...base, op: 'decaps', backend: 'webcrypto-native', async: true,
      setup: async () => {
        const kp = await nativeGen(alg, ['encapsulateBits', 'decapsulateBits']);
        const s = subtle() as AnySubtle;
        const { ciphertext, sharedKey } = await s.encapsulateBits({ name: alg }, kp.publicKey);
        check(eq(u8(await s.decapsulateBits({ name: alg }, kp.privateKey, ciphertext)), u8(sharedKey)), `${alg} native decaps`);
        return () => s.decapsulateBits({ name: alg }, kp.privateKey, ciphertext);
      },
    },
  ];
  return ops;
}

function xwingOps(): OpSpec[] {
  const base = { exp: 'E1' as const, family: 'X-Wing', alg: 'X-Wing', backend: 'noble' as const, async: false };
  const k = ml_kem768_x25519;
  return [
    { ...base, op: 'keygen', setup: async () => () => k.keygen() },
    {
      ...base, op: 'encaps',
      setup: async () => {
        const { publicKey } = k.keygen();
        return () => k.encapsulate(publicKey);
      },
    },
    {
      ...base, op: 'decaps',
      setup: async () => {
        const { publicKey, secretKey } = k.keygen();
        const { cipherText, sharedSecret } = k.encapsulate(publicKey);
        check(eq(k.decapsulate(cipherText, secretKey), sharedSecret), 'X-Wing decaps');
        return () => k.decapsulate(cipherText, secretKey);
      },
    },
  ];
}

// ---------------------------------------------------------------------------
// E2: ML-DSA
// ---------------------------------------------------------------------------
function dsaOps(alg: keyof typeof NOBLE_DSA): OpSpec[] {
  const base = { exp: 'E2' as const, family: 'ML-DSA', alg };
  const noble = NOBLE_DSA[alg];
  return [
    { ...base, op: 'keygen', backend: 'noble', async: false, setup: async () => () => noble.keygen() },
    {
      ...base, op: 'sign', backend: 'noble', async: false,
      setup: async () => {
        const { secretKey } = noble.keygen();
        return () => noble.sign(MSG, secretKey);
      },
    },
    {
      ...base, op: 'verify', backend: 'noble', async: false,
      setup: async () => {
        const { secretKey, publicKey } = noble.keygen();
        const sig = noble.sign(MSG, secretKey);
        check(noble.verify(sig, MSG, publicKey), `${alg} noble verify`);
        return () => noble.verify(sig, MSG, publicKey);
      },
    },
    {
      ...base, op: 'keygen', backend: 'liboqs-wasm', async: false,
      setup: async () => {
        const s = await oqs<OqsSig>(alg);
        return () => s.generateKeyPair();
      },
    },
    {
      ...base, op: 'sign', backend: 'liboqs-wasm', async: false,
      setup: async () => {
        const s = await oqs<OqsSig>(alg);
        const { secretKey } = s.generateKeyPair();
        return () => s.sign(MSG, secretKey);
      },
    },
    {
      ...base, op: 'verify', backend: 'liboqs-wasm', async: false,
      setup: async () => {
        const s = await oqs<OqsSig>(alg);
        const { secretKey, publicKey } = s.generateKeyPair();
        const sig = s.sign(MSG, secretKey);
        check(s.verify(MSG, sig, publicKey), `${alg} liboqs verify`);
        check(noble.verify(sig, MSG, publicKey), `${alg} noble verifies liboqs sig`);
        return () => s.verify(MSG, sig, publicKey);
      },
    },
    {
      ...base, op: 'keygen', backend: 'webcrypto-native', async: true,
      setup: async () => {
        await nativeGen(alg, ['sign', 'verify']);
        return () => subtle().generateKey({ name: alg }, true, ['sign', 'verify']);
      },
    },
    {
      ...base, op: 'sign', backend: 'webcrypto-native', async: true,
      setup: async () => {
        const kp = await nativeGen(alg, ['sign', 'verify']);
        return () => subtle().sign({ name: alg }, kp.privateKey, MSG);
      },
    },
    {
      ...base, op: 'verify', backend: 'webcrypto-native', async: true,
      setup: async () => {
        const kp = await nativeGen(alg, ['sign', 'verify']);
        const sig = await subtle().sign({ name: alg }, kp.privateKey, MSG);
        check(await subtle().verify({ name: alg }, kp.publicKey, sig, MSG), `${alg} native verify`);
        return () => subtle().verify({ name: alg }, kp.publicKey, sig, MSG);
      },
    },
  ];
}

// ---------------------------------------------------------------------------
// E3: classical baselines
// ---------------------------------------------------------------------------
function classicalOps(): OpSpec[] {
  const x = { exp: 'E3' as const, family: 'X25519', alg: 'X25519' };
  const ed = { exp: 'E3' as const, family: 'Ed25519', alg: 'Ed25519' };
  return [
    { ...x, op: 'keygen', backend: 'noble', async: false, setup: async () => () => x25519.keygen() },
    {
      ...x, op: 'derive', backend: 'noble', async: false,
      setup: async () => {
        const a = x25519.keygen();
        const b = x25519.keygen();
        check(eq(x25519.getSharedSecret(a.secretKey, b.publicKey), x25519.getSharedSecret(b.secretKey, a.publicKey)), 'x25519 noble');
        return () => x25519.getSharedSecret(a.secretKey, b.publicKey);
      },
    },
    {
      ...x, op: 'keygen', backend: 'webcrypto-native', async: true,
      setup: async () => {
        await nativeGen('X25519', ['deriveBits']);
        return () => subtle().generateKey({ name: 'X25519' }, true, ['deriveBits']);
      },
    },
    {
      ...x, op: 'derive', backend: 'webcrypto-native', async: true,
      setup: async () => {
        const a = await nativeGen('X25519', ['deriveBits']);
        const b = await nativeGen('X25519', ['deriveBits']);
        const alg = { name: 'X25519', public: b.publicKey } as unknown as EcdhKeyDeriveParams;
        return () => subtle().deriveBits(alg, a.privateKey, 256);
      },
    },
    { ...ed, op: 'keygen', backend: 'noble', async: false, setup: async () => () => ed25519.keygen() },
    {
      ...ed, op: 'sign', backend: 'noble', async: false,
      setup: async () => {
        const { secretKey } = ed25519.keygen();
        return () => ed25519.sign(MSG, secretKey);
      },
    },
    {
      ...ed, op: 'verify', backend: 'noble', async: false,
      setup: async () => {
        const { secretKey, publicKey } = ed25519.keygen();
        const sig = ed25519.sign(MSG, secretKey);
        check(ed25519.verify(sig, MSG, publicKey), 'ed25519 noble verify');
        return () => ed25519.verify(sig, MSG, publicKey);
      },
    },
    {
      ...ed, op: 'keygen', backend: 'webcrypto-native', async: true,
      setup: async () => {
        await nativeGen('Ed25519', ['sign', 'verify']);
        return () => subtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      },
    },
    {
      ...ed, op: 'sign', backend: 'webcrypto-native', async: true,
      setup: async () => {
        const kp = await nativeGen('Ed25519', ['sign', 'verify']);
        return () => subtle().sign({ name: 'Ed25519' }, kp.privateKey, MSG);
      },
    },
    {
      ...ed, op: 'verify', backend: 'webcrypto-native', async: true,
      setup: async () => {
        const kp = await nativeGen('Ed25519', ['sign', 'verify']);
        const sig = await subtle().sign({ name: 'Ed25519' }, kp.privateKey, MSG);
        check(await subtle().verify({ name: 'Ed25519' }, kp.publicKey, sig, MSG), 'ed25519 native verify');
        return () => subtle().verify({ name: 'Ed25519' }, kp.publicKey, sig, MSG);
      },
    },
  ];
}

// ---------------------------------------------------------------------------
// E4: symmetric layer (AES-256-GCM throughput, HMAC/HKDF ratchet chain step)
// ---------------------------------------------------------------------------
export const AES_SIZES = [64, 1024, 16 * 1024, 256 * 1024, 1024 * 1024];

function symmetricOps(): OpSpec[] {
  const aes = { exp: 'E4' as const, family: 'AES-256-GCM', alg: 'AES-256-GCM', backend: 'webcrypto-native' as const, async: true };
  const kdf = { exp: 'E4' as const, family: 'KDF', alg: 'HMAC/HKDF-SHA-256', backend: 'webcrypto-native' as const, async: true };
  const aesKey = () => subtle().importKey('raw', rand(32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  // NOTE: a fixed IV is used only because this is a throughput benchmark on
  // random data; the protocol derives a fresh IV per message key.
  const iv = rand(12);
  const ops: OpSpec[] = [];
  for (const size of AES_SIZES) {
    ops.push({
      ...aes, op: 'encrypt', bytes: size,
      setup: async () => {
        const key = await aesKey();
        const pt = rand(size);
        return () => subtle().encrypt({ name: 'AES-GCM', iv }, key, pt);
      },
    });
    ops.push({
      ...aes, op: 'decrypt', bytes: size,
      setup: async () => {
        const key = await aesKey();
        const pt = rand(size);
        const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, pt);
        check(eq(u8(await subtle().decrypt({ name: 'AES-GCM', iv }, key, ct)), pt), 'aes-gcm roundtrip');
        return () => subtle().decrypt({ name: 'AES-GCM', iv }, key, ct);
      },
    });
  }

  // Ratchet chain step, exactly as strategy section 4.4:
  //   mk = HMAC(CK, 0x01); CK' = HMAC(CK, 0x02); key||iv = HKDF(0, mk, "Krypt-MK", 44)
  const zeros = new Uint8Array(32);
  const info = enc.encode('Krypt-MK');
  const one = new Uint8Array([1]);
  const two = new Uint8Array([2]);
  async function chainStep(ck: Bytes): Promise<{ ck: Bytes; key: Bytes; iv: Bytes }> {
    const s = subtle();
    const ckKey = await s.importKey('raw', ck, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const [mk, next] = await Promise.all([s.sign('HMAC', ckKey, one), s.sign('HMAC', ckKey, two)]);
    const mkKey = await s.importKey('raw', mk, 'HKDF', false, ['deriveBits']);
    const kiv = new Uint8Array(await s.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: zeros, info }, mkKey, 44 * 8));
    return { ck: new Uint8Array(next), key: kiv.slice(0, 32), iv: kiv.slice(32) };
  }
  ops.push({
    ...kdf, op: 'chain-step',
    setup: async () => {
      let ck = rand(32);
      return async () => {
        const r = await chainStep(ck);
        ck = r.ck;
        return r;
      };
    },
  });
  // Root step: KDF_RK(RK, ss, ctx) = HKDF(salt=RK, ikm=ss, info="Krypt-RK"||ctx, 64)
  ops.push({
    ...kdf, op: 'root-step',
    setup: async () => {
      const rk = rand(32);
      const ss = rand(32);
      const ctxInfo = new Uint8Array([...enc.encode('Krypt-RK'), ...rand(4 + 32 + 32)]);
      return async () => {
        const k = await subtle().importKey('raw', ss, 'HKDF', false, ['deriveBits']);
        return subtle().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: rk, info: ctxInfo }, k, 512);
      };
    },
  });
  // Full per-message symmetric cost: chain step + AES-GCM seal of a 1 KB message.
  ops.push({
    ...kdf, alg: 'chain-step+AES-256-GCM', op: 'seal', bytes: 1024,
    setup: async () => {
      let ck = rand(32);
      const pt = rand(1024);
      return async () => {
        const r = await chainStep(ck);
        ck = r.ck;
        const k = await subtle().importKey('raw', r.key, { name: 'AES-GCM' }, false, ['encrypt']);
        return subtle().encrypt({ name: 'AES-GCM', iv: r.iv }, k, pt);
      };
    },
  });
  return ops;
}

export function allOps(extra: OpSpec[] = []): OpSpec[] {
  return [
    ...kemOps('ML-KEM-512'),
    ...kemOps('ML-KEM-768'),
    ...kemOps('ML-KEM-1024'),
    ...xwingOps(),
    ...dsaOps('ML-DSA-44'),
    ...dsaOps('ML-DSA-65'),
    ...dsaOps('ML-DSA-87'),
    ...classicalOps(),
    ...symmetricOps(),
    ...extra,
  ];
}

export async function runOp(spec: OpSpec, cfg: BenchConfig): Promise<OpResult> {
  const { exp, family, alg, op, backend, bytes } = spec;
  const res: OpResult = { id: opId(spec), exp, family, alg, op, backend, status: 'ok', bytes };
  try {
    const fn = await spec.setup();
    res.measurement = await measure(fn, spec.async, cfg);
    if (bytes !== undefined) res.mbpsMedian = bytes / res.measurement.stats.median * 1e3; // B/ns*1e9/1e6
  } catch (e) {
    res.status = e instanceof Unsupported ? 'unsupported' : 'error';
    res.reason = `${(e as Error).name}: ${(e as Error).message}`;
  }
  return res;
}

export async function runAll(
  ops: OpSpec[],
  cfg: BenchConfig,
  filter: RegExp | null,
  onProgress?: (done: number, total: number, r: OpResult) => void,
): Promise<OpResult[]> {
  const selected = filter ? ops.filter((o) => filter.test(opId(o))) : ops;
  const out: OpResult[] = [];
  for (const spec of selected) {
    const r = await runOp(spec, cfg);
    out.push(r);
    onProgress?.(out.length, selected.length, r);
  }
  return out;
}
