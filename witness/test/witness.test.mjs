// Runs the witness against a fake Krypt log on localhost. No network needed.
//
// The fake log keeps an honest MerkleLog and can be switched to misbehave:
// serve a head from a rewritten history, a different root at the same size,
// an older head, or a badly signed head.

import { ml_dsa44, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  MemoryNodeStore,
  MerkleLog,
  cosignatureFromJson,
  fromBase64,
  hashLeaf,
  hashesToJson,
  logIdFromPublicKey,
  signTreeHead,
  sthFromJson,
  sthToJson,
  toBase64,
  utf8,
  verifyCosignature,
  verifyTreeHead,
} from "../lib/krypt-shared/index.js";
import { EXIT, runWitness } from "../witness.mjs";

const WITNESS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(1));
const witnessSeed = new Uint8Array(32).fill(2);
const witnessPk = ml_dsa44.keygen(witnessSeed).publicKey;
const T0 = 1_760_000_000_000;

/** A log whose behaviour the test controls. */
class FakeLog {
  constructor() {
    this.honest = new MerkleLog(new MemoryNodeStore());
    this.served = this.honest; // the tree whose head and proofs we serve
    this.clock = T0;
    this.sthOverride = null; // JSON to serve instead of the real head
  }

  async grow(n, tree = this.honest, tag = "leaf") {
    for (let i = 0; i < n; i++) await tree.append(await hashLeaf(utf8(`${tag}-${tree.size}`)));
  }

  async head(tree = this.served, size = tree.size) {
    this.clock += 1000;
    return signTreeHead({ treeSize: size, rootHash: await tree.root(size), timestampMs: this.clock }, (m) =>
      ml_dsa87.sign(m, logKey.secretKey),
    );
  }

  async handle(url) {
    if (url.pathname === "/kt/sth") return this.sthOverride ?? sthToJson(await this.head());
    if (url.pathname === "/kt/consistency") {
      const from = Number(url.searchParams.get("from"));
      const to = Number(url.searchParams.get("to"));
      return { from, to, proof: hashesToJson(await this.served.consistencyProof(from, to)) };
    }
    return null;
  }
}

let server;
let baseUrl;
let fake;
const requests = [];

before(async () => {
  server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://x");
    requests.push(url.pathname + url.search);
    try {
      const body = await fake.handle(url);
      res.writeHead(body ? 200 : 404, { "content-type": "application/json" });
      res.end(JSON.stringify(body ?? { error: "not found" }));
    } catch (err) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

function freshDir() {
  return mkdtempSync(join(tmpdir(), "krypt-witness-"));
}

function config(dir, overrides = {}) {
  return {
    logUrl: baseUrl,
    logPublicKey: logKey.publicKey,
    witnessSeed,
    witnessName: "test-witness",
    dir,
    refreshMinutes: 360,
    fetchTimeoutMs: 5000,
    ...overrides,
  };
}

const quiet = { log: () => {}, now: () => fake.clock + 5000 };
const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));

async function assertPublishedCosignatureValid(dir) {
  const latest = readJson(join(dir, "public", "latest.json"));
  const sth = sthFromJson(latest.sth);
  assert.equal(latest.witness.publicKey, toBase64(witnessPk));
  assert.ok(await verifyTreeHead(sth, (m, s) => ml_dsa87.verify(s, m, logKey.publicKey)), "log signature");
  const logId = await logIdFromPublicKey(logKey.publicKey);
  assert.equal(latest.log.id, toBase64(logId));
  const ok = await verifyCosignature(sth, logId, cosignatureFromJson(latest.cosignature), (m, s) =>
    ml_dsa44.verify(s, m, witnessPk),
  );
  assert.ok(ok, "witness cosignature");
  return latest;
}

describe("witness against a fake log", () => {
  it("first run trusts and cosigns the current head", async () => {
    fake = new FakeLog();
    await fake.grow(5);
    const dir = freshDir();
    const r = await runWitness(config(dir), quiet);
    assert.equal(r.code, EXIT.OK);
    assert.equal(r.status, "cosigned");
    const latest = await assertPublishedCosignatureValid(dir);
    assert.equal(latest.sth.treeSize, 5);
    assert.deepEqual(readJson(join(dir, "state", "last.json")).sth, latest.sth);
    rmSync(dir, { recursive: true });
  });

  it("normal growth: verifies consistency and cosigns the new head", async () => {
    fake = new FakeLog();
    await fake.grow(5);
    const dir = freshDir();
    assert.equal((await runWitness(config(dir), quiet)).code, EXIT.OK);

    // Nothing new: no new cosignature inside the refresh window.
    const before = readFileSync(join(dir, "public", "latest.json"), "utf8");
    fake.sthOverride = sthToJson(await fake.head(fake.honest, 5));
    const same = await runWitness(config(dir), quiet);
    assert.equal(same.status, "unchanged");
    assert.equal(readFileSync(join(dir, "public", "latest.json"), "utf8"), before);
    fake.sthOverride = null;

    for (const add of [1, 7, 50]) {
      requests.length = 0;
      const from = fake.honest.size;
      await fake.grow(add);
      const r = await runWitness(config(dir), quiet);
      assert.equal(r.code, EXIT.OK, r.message);
      assert.ok(requests.includes(`/kt/consistency?from=${from}&to=${fake.honest.size}`));
      const latest = await assertPublishedCosignatureValid(dir);
      assert.equal(latest.sth.treeSize, fake.honest.size);
    }
    rmSync(dir, { recursive: true });
  });

  it("re-cosigns an unchanged head once the refresh window passes", async () => {
    fake = new FakeLog();
    await fake.grow(3);
    const dir = freshDir();
    await runWitness(config(dir), quiet);
    const first = readJson(join(dir, "public", "latest.json")).cosignature.timestamp;
    fake.sthOverride = sthToJson(await fake.head(fake.honest, 3));
    const r = await runWitness(config(dir, { refreshMinutes: 0 }), { log: () => {}, now: () => first + 60_000 });
    assert.equal(r.status, "cosigned");
    assert.equal(readJson(join(dir, "public", "latest.json")).cosignature.timestamp, first + 60_000);
    rmSync(dir, { recursive: true });
  });

  it("fork detection: a rewritten history is refused with evidence", async () => {
    fake = new FakeLog();
    await fake.grow(8);
    const dir = freshDir();
    assert.equal((await runWitness(config(dir), quiet)).code, EXIT.OK);
    const cosigned = readFileSync(join(dir, "public", "latest.json"), "utf8");

    // The log rewrites leaf 3 and keeps growing on the forked history.
    const forked = new MerkleLog(new MemoryNodeStore());
    for (let i = 0; i < 8; i++) await forked.append(await hashLeaf(utf8(i === 3 ? "rogue-key-for-bob" : `leaf-${i}`)));
    await fake.grow(4, forked);
    fake.served = forked;

    const r = await runWitness(config(dir), quiet);
    assert.equal(r.code, EXIT.ALERT);
    assert.equal(r.status, "inconsistent");
    // Nothing was cosigned or published.
    assert.equal(readFileSync(join(dir, "public", "latest.json"), "utf8"), cosigned);
    assert.equal(readJson(join(dir, "state", "last.json")).sth.treeSize, 8);

    // The alert holds both signed heads and the failing proof, all checkable offline.
    const alert = readJson(join(dir, "state", "ALERT.json"));
    assert.equal(alert.previous.treeSize, 8);
    assert.equal(alert.offered.treeSize, 12);
    assert.equal(alert.proof.from, 8);
    assert.equal(alert.proof.to, 12);
    assert.ok(alert.proof.proof.length > 0);
    const verifyLog = (m, s) => ml_dsa87.verify(s, m, fromBase64(alert.logPublicKey));
    assert.ok(await verifyTreeHead(sthFromJson(alert.previous), verifyLog));
    assert.ok(await verifyTreeHead(sthFromJson(alert.offered), verifyLog));

    // Sticky: even an honest head is not cosigned until a human clears the alert.
    fake.served = fake.honest;
    const again = await runWitness(config(dir), quiet);
    assert.equal(again.code, EXIT.ALERT);
    assert.equal(again.status, "halted");
    rmSync(dir, { recursive: true });
  });

  it("fork detection: two different roots for the same size", async () => {
    fake = new FakeLog();
    await fake.grow(6);
    const dir = freshDir();
    await runWitness(config(dir), quiet);
    const other = new MerkleLog(new MemoryNodeStore());
    await fake.grow(6, other, "evil");
    fake.served = other;
    const r = await runWitness(config(dir), quiet);
    assert.equal(r.code, EXIT.ALERT);
    assert.equal(r.status, "fork");
    assert.ok(existsSync(join(dir, "state", "ALERT.json")));
    rmSync(dir, { recursive: true });
  });

  it("an older head: consistent means stale (refused, no alert); inconsistent is a fork", async () => {
    fake = new FakeLog();
    await fake.grow(10);
    const dir = freshDir();
    await runWitness(config(dir), quiet);

    fake.sthOverride = sthToJson(await fake.head(fake.honest, 6));
    const stale = await runWitness(config(dir), quiet);
    assert.equal(stale.code, EXIT.REFUSED);
    assert.equal(stale.status, "stale");
    assert.ok(!existsSync(join(dir, "state", "ALERT.json")));

    const other = new MerkleLog(new MemoryNodeStore());
    await fake.grow(10, other, "evil");
    fake.served = other;
    fake.sthOverride = sthToJson(await fake.head(other, 6));
    const fork = await runWitness(config(dir), quiet);
    assert.equal(fork.code, EXIT.ALERT);
    rmSync(dir, { recursive: true });
  });

  it("refuses badly signed, future-dated and wrong-key heads without an alert", async () => {
    fake = new FakeLog();
    await fake.grow(4);
    const dir = freshDir();
    await runWitness(config(dir), quiet);
    await fake.grow(1);

    const good = sthToJson(await fake.head());
    fake.sthOverride = { ...good, signature: toBase64(ml_dsa87.sign(utf8("other"), logKey.secretKey)) };
    assert.equal((await runWitness(config(dir), quiet)).status, "bad-signature");

    fake.sthOverride = sthToJson(
      await signTreeHead(
        { treeSize: 5, rootHash: await fake.honest.root(), timestampMs: fake.clock + 3_600_000 },
        (m) => ml_dsa87.sign(m, logKey.secretKey),
      ),
    );
    assert.equal((await runWitness(config(dir), quiet)).status, "future");

    fake.sthOverride = null;
    const otherKey = ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey;
    assert.equal((await runWitness(config(dir, { logPublicKey: otherKey }), quiet)).status, "bad-signature");
    assert.ok(!existsSync(join(dir, "state", "ALERT.json")));
    assert.equal(readJson(join(dir, "state", "last.json")).sth.treeSize, 4);
    rmSync(dir, { recursive: true });
  });

  it("CLI exits 0 on success and 1 on a fork", async () => {
    fake = new FakeLog();
    await fake.grow(3);
    const dir = freshDir();
    const env = {
      ...process.env,
      KRYPT_LOG_URL: baseUrl,
      KRYPT_LOG_PUBKEY: toBase64(logKey.publicKey),
      WITNESS_SK: toBase64(witnessSeed),
      KRYPT_WITNESS_DIR: dir,
    };
    const run = () =>
      new Promise((resolve) => {
        execFile(process.execPath, [join(WITNESS_DIR, "witness.mjs")], { env }, (err, stdout, stderr) =>
          resolve({ code: err ? err.code : 0, out: stdout + stderr }),
        );
      });
    // The fake log's clock is in 2025, behind the real clock the CLI uses, so no "future" refusal.
    const ok = await run();
    assert.equal(ok.code, 0, ok.out);
    const other = new MerkleLog(new MemoryNodeStore());
    await fake.grow(3, other, "evil");
    fake.served = other;
    const bad = await run();
    assert.equal(bad.code, 1, bad.out);
    assert.match(bad.out, /fork/);
    const missing = await new Promise((resolve) =>
      execFile(process.execPath, [join(WITNESS_DIR, "witness.mjs")], { env: { PATH: process.env.PATH } }, (err) =>
        resolve(err?.code),
      ),
    );
    assert.equal(missing, 2);
    rmSync(dir, { recursive: true });
  });
});
