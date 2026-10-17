// E10 (plan step 3.24): Node native ML-KEM / ML-DSA vs noble (and liboqs WASM)
// in Node, using the same harness and statistics as the browser page.
//
// Backends in Node:
//   node-crypto       node:crypto KeyObject API (generateKeyPairSync('ml-kem-768'),
//                     crypto.encapsulate/decapsulate, crypto.sign/verify)  [Node >= 24.7]
//   webcrypto-native  globalThis.crypto.subtle with the WICG Modern Algorithms
//                     methods (encapsulateBits, ML-DSA sign) that Node also ships
//   noble, liboqs-wasm  same code as in the browser
//
//   npx tsx scripts/run-node.ts [--quick] [--filter re] [--out results/<date>]

import * as nodeCrypto from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { parseArgs } from 'node:util';
import os from 'node:os';
import { runSuite } from '../src/run.ts';
import { Unsupported, type OpSpec } from '../src/experiments.ts';

const ROOT = resolve(import.meta.dirname, '..');
const { values: args } = parseArgs({
  options: {
    quick: { type: 'boolean', default: false },
    filter: { type: 'string' },
    out: { type: 'string' },
    run: { type: 'string', default: '1' },
  },
});

const MSG = Buffer.from('Krypt-init benchmark transcript hash placeholder 0123456789abcdef');
const c = nodeCrypto as typeof nodeCrypto & {
  encapsulate?: (key: nodeCrypto.KeyObject) => { sharedKey: Buffer; ciphertext: Buffer };
  decapsulate?: (key: nodeCrypto.KeyObject, ct: Buffer) => Buffer;
};

function nodeKeyPair(type: string) {
  try {
    return (nodeCrypto.generateKeyPairSync as (t: string) => nodeCrypto.KeyPairKeyObjectResult)(type);
  } catch (e) {
    throw new Unsupported(`generateKeyPairSync('${type}'): ${(e as Error).message}`);
  }
}

function nodeOps(): OpSpec[] {
  const ops: OpSpec[] = [];
  for (const n of [512, 768, 1024]) {
    const alg = `ML-KEM-${n}`;
    const type = `ml-kem-${n}`;
    const base = { exp: 'E1' as const, family: 'ML-KEM', alg, backend: 'node-crypto' as const, async: false };
    ops.push({ ...base, op: 'keygen', setup: async () => (nodeKeyPair(type), () => nodeKeyPair(type)) });
    ops.push({
      ...base, op: 'encaps',
      setup: async () => {
        if (!c.encapsulate) throw new Unsupported('crypto.encapsulate missing (Node < 24.7)');
        const { publicKey } = nodeKeyPair(type);
        return () => c.encapsulate!(publicKey);
      },
    });
    ops.push({
      ...base, op: 'decaps',
      setup: async () => {
        if (!c.decapsulate) throw new Unsupported('crypto.decapsulate missing (Node < 24.7)');
        const { publicKey, privateKey } = nodeKeyPair(type);
        const { ciphertext, sharedKey } = c.encapsulate!(publicKey);
        if (!c.decapsulate(privateKey, ciphertext).equals(sharedKey)) throw new Error('node decaps self-check');
        return () => c.decapsulate!(privateKey, ciphertext);
      },
    });
  }
  for (const n of [44, 65, 87]) {
    const alg = `ML-DSA-${n}`;
    const type = `ml-dsa-${n}`;
    const base = { exp: 'E2' as const, family: 'ML-DSA', alg, backend: 'node-crypto' as const, async: false };
    ops.push({ ...base, op: 'keygen', setup: async () => (nodeKeyPair(type), () => nodeKeyPair(type)) });
    ops.push({
      ...base, op: 'sign',
      setup: async () => {
        const { privateKey } = nodeKeyPair(type);
        return () => nodeCrypto.sign(null, MSG, privateKey);
      },
    });
    ops.push({
      ...base, op: 'verify',
      setup: async () => {
        const { privateKey, publicKey } = nodeKeyPair(type);
        const sig = nodeCrypto.sign(null, MSG, privateKey);
        if (!nodeCrypto.verify(null, MSG, publicKey, sig)) throw new Error('node verify self-check');
        return () => nodeCrypto.verify(null, MSG, publicKey, sig);
      },
    });
  }
  // Classical, node:crypto (OpenSSL)
  const x = { exp: 'E3' as const, family: 'X25519', alg: 'X25519', backend: 'node-crypto' as const, async: false };
  ops.push({ ...x, op: 'keygen', setup: async () => () => nodeKeyPair('x25519') });
  ops.push({
    ...x, op: 'derive',
    setup: async () => {
      const a = nodeKeyPair('x25519');
      const b = nodeKeyPair('x25519');
      return () => nodeCrypto.diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey });
    },
  });
  const ed = { exp: 'E3' as const, family: 'Ed25519', alg: 'Ed25519', backend: 'node-crypto' as const, async: false };
  ops.push({ ...ed, op: 'keygen', setup: async () => () => nodeKeyPair('ed25519') });
  ops.push({
    ...ed, op: 'sign',
    setup: async () => {
      const { privateKey } = nodeKeyPair('ed25519');
      return () => nodeCrypto.sign(null, MSG, privateKey);
    },
  });
  ops.push({
    ...ed, op: 'verify',
    setup: async () => {
      const { privateKey, publicKey } = nodeKeyPair('ed25519');
      const sig = nodeCrypto.sign(null, MSG, privateKey);
      return () => nodeCrypto.verify(null, MSG, publicKey, sig);
    },
  });
  return ops;
}

async function main() {
  // Node prints an ExperimentalWarning per Modern-Algorithms method; keep the log readable.
  process.removeAllListeners('warning');
  const today = new Date().toISOString().slice(0, 10);
  const outDir = resolve(ROOT, args.out ?? `results/${today}`);
  await mkdir(outDir, { recursive: true });
  const cpus = os.cpus();
  const doc = await runSuite({
    quick: args.quick!,
    filter: args.filter ?? null,
    context: 'node',
    extraOps: nodeOps(),
    extraEnv: {
      userAgent: `Node.js ${process.version} (${process.platform} ${process.arch})`,
      nodeVersion: process.version,
      opensslVersion: process.versions.openssl,
      cpuModel: cpus[0]?.model,
      hardwareConcurrency: cpus.length,
      totalMemGB: Math.round(os.totalmem() / 2 ** 30),
    },
    onProgress: (done, total, r) =>
      process.stdout.write(`\r[node] ${done}/${total} ${r.id} ${r.status === 'ok' ? '' : r.status}`.padEnd(100)),
  });
  process.stdout.write('\n');
  const file = resolve(outDir, `node-${args.run}.json`);
  await writeFile(file, JSON.stringify({ ...doc, runner: { browser: 'node', browserVersion: process.version, run: Number(args.run) } }, null, 1));
  const ok = doc.results.filter((r) => r.status === 'ok').length;
  console.log(`[node] ${ok}/${doc.results.length} ok in ${(doc.durationMs / 1000).toFixed(0)} s -> ${relative(ROOT, file)}`);
  for (const r of doc.results.filter((r) => r.status !== 'ok')) console.log(`  ${r.status}: ${r.id} ${r.reason}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
