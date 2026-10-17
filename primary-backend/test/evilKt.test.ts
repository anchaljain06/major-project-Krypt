import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import express from "express";
import type { Server } from "http";
import type { AddressInfo } from "net";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  KtOp,
  checkSthChain,
  decodeLeaf,
  hashUsername,
  parseConsistencyResponse,
  parseLookupResponse,
  selfMonitor,
  sha256,
  sthFromJson,
  toBase64,
  verifyLookup,
  verifyOwnerSig,
} from "../src/vendor/krypt-shared/index.js";
import { newIdentity, signedLeaf } from "./ktHelpers.js";

// Evil relay KT attacks (plan 2.25): each one works when switched on, is
// caught by the client/witness checks in shared/, and the honest path
// refuses or ignores it.

vi.mock("../src/db.js", () => ({ prisma: {} }));
process.env.AUTH_TOKEN_SECRET = "evil-kt-test-secret";
const { issueToken, requireAuth } = await import("../src/auth.js");
const { KtLog, logKeyFromSeed, memoryKtStorage } = await import("../src/kt.js");
const { ktApiRouter, ktPublicRouter, setKtEvil } = await import("../src/ktRoutes.js");
const { createEvilKt, isForkTarget, parseEvilConfig } = await import("../src/evil.js");

const key = logKeyFromSeed(new Uint8Array(32).fill(8));
const verifySth = (m: Uint8Array, s: Uint8Array) => key.verify(m, s);
const verifySig = (m: Uint8Array, s: Uint8Array, pk: Uint8Array) => ml_dsa87.verify(s, m, pk);

const bob = newIdentity(31);
const mallory = newIdentity(32);
const keys = new Map([
  ["bob", bob.identityKeyPub],
  ["mallory", mallory.identityKeyPub],
]);
const users = new Map([
  ["u-bob", { username: "bob", identityKeyPub: bob.identityKeyPub }],
  ["u-mallory", { username: "mallory", identityKeyPub: mallory.identityKeyPub }],
]);
const malloryToken = issueToken({ userId: "u-mallory", username: "mallory" });
const bobToken = issueToken({ userId: "u-bob", username: "bob" });

let log: InstanceType<typeof KtLog>;
let server: Server;
let base: string;
beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/kt", ktPublicRouter(() => log));
  app.use("/api", requireAuth, express.Router().use("/kt", ktApiRouter(() => log, async (id) => users.get(id) ?? null)));
  server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => {
  setKtEvil(null);
  server.close();
});

beforeEach(async () => {
  setKtEvil(null);
  log = new KtLog(memoryKtStorage(), key, { sthIntervalMs: 0 });
  // Bob registers honestly.
  const reg = await signedLeaf({ op: KtOp.Register, username: "bob", keyVersion: 1, about: bob, signer: bob });
  await log.append(reg.bytes, reg.ownerSig);
});

const get = async (path: string, headers: Record<string, string> = {}) => {
  const r = await fetch(base + path, { headers });
  return { status: r.status, body: (await r.json()) as any };
};
const post = async (path: string, body: unknown, token?: string) => {
  const r = await fetch(base + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: (await r.json()) as any };
};
const evilFor = (mode: string, extra: Record<string, string> = {}) =>
  createEvilKt(parseEvilConfig({ EVIL_MODE: mode, EVIL_SWAP_WITH: "mallory", ...extra })!, log, async (u) => keys.get(u) ?? null);

/** What Bob's client does on login: self-monitor every leaf since his last check. */
async function bobMonitor() {
  const sth = sthFromJson((await get("/kt/sth")).body);
  const page = (await get(`/kt/leaves?from=0&to=${sth.treeSize}`)).body;
  const leaves = page.leaves.map((e: any) => ({ index: e.index, leaf: decodeLeaf(Uint8Array.from(Buffer.from(e.leaf, "base64"))) }));
  return selfMonitor(
    await hashUsername("bob"),
    [{ keyVersion: 1, mldsaPkHash: await sha256(bob.dsa.publicKey), mlkemPkHash: await sha256(bob.kem.publicKey) }],
    leaves,
  );
}

describe("parseEvilConfig", () => {
  it("knows the KT attacks and their settings", () => {
    const c = parseEvilConfig({
      EVIL_MODE: "kt_rogue_leaf,kt_fork,kt_rewrite",
      EVIL_KT_VICTIM: "bob",
      EVIL_FORK_UA: "Firefox",
      EVIL_KT_REWRITE_INDEX: "2",
    })!;
    expect([...c.attacks]).toEqual(["kt_rogue_leaf", "kt_fork", "kt_rewrite"]);
    expect(c).toMatchObject({ ktVictim: "bob", forkUserAgent: "Firefox", rewriteIndex: 2 });
    expect(isForkTarget({ headers: { "user-agent": "Mozilla/5.0 firefox/130" }, query: {} }, c)).toBe(true);
    expect(isForkTarget({ headers: { "user-agent": "Chrome" }, query: {} }, c)).toBe(false);
    expect(isForkTarget({ headers: {}, query: { fork: "1" } }, c)).toBe(true);
    expect(createEvilKt(parseEvilConfig({ EVIL_MODE: "replay" })!, log, async () => null)).toBeNull();
  });
});

describe("kt_rogue_leaf", () => {
  it("honest server: refuses a leaf for someone else, and a leaf with a forged signature", async () => {
    // Mallory submits a leaf putting her key under Bob's name.
    const rogue = await signedLeaf({ op: KtOp.Rotate, username: "bob", keyVersion: 2, about: mallory, signer: mallory });
    const body = { leaf: toBase64(rogue.bytes), ownerSig: toBase64(rogue.ownerSig) };
    expect((await post("/api/kt/register", body, malloryToken)).status).toBe(403);
    // Even as Bob, a rotation not signed by Bob's previous key is refused.
    users.set("u-bob", { username: "bob", identityKeyPub: mallory.identityKeyPub });
    try {
      const r = await post("/api/kt/register", { ...body, signerPk: toBase64(mallory.dsa.publicKey) }, bobToken);
      expect(r.status).toBe(400);
    } finally {
      users.set("u-bob", { username: "bob", identityKeyPub: bob.identityKeyPub });
    }
    // And the injection endpoint does not exist.
    expect((await post("/kt/evil/rogue-leaf?victim=bob", {})).status).toBe(404);
    expect(await bobMonitor()).toEqual([]);
  });

  it("evil server: plants Mallory's key under Bob's name; Bob's monitor and signature checks catch it", async () => {
    setKtEvil(evilFor("kt_rogue_leaf"));
    const r = await post("/kt/evil/rogue-leaf?victim=bob", {});
    expect(r.body).toEqual({ leafIndex: 1 });

    const lookup = parseLookupResponse((await get("/kt/proof?user=bob")).body);
    const leaf = decodeLeaf(lookup.leaf);
    expect(leaf.mldsaPkHash).toEqual(await sha256(mallory.dsa.publicKey));
    // Alice's lookup alone cannot tell (Phase 1 log, rotation leaf)...
    expect((await verifyLookup({ username: "bob", response: lookup, verifySth, mldsaPk: mallory.dsa.publicKey })).ok).toBe(true);
    // ...but the owner signature does not verify under Bob's previous key,
    expect(await verifyOwnerSig(leaf, lookup.ownerSig, bob.dsa.publicKey, verifySig)).toBe(false);
    // and Bob's self-monitoring flags the unknown key.
    expect((await bobMonitor()).map((a) => a.kind)).toEqual(["unknown-key"]);

    // Register checks are off too: Mallory can submit a leaf for Bob.
    const rogue = await signedLeaf({ op: KtOp.Rotate, username: "bob", keyVersion: 3, about: mallory, signer: mallory });
    expect((await post("/api/kt/register", { leaf: toBase64(rogue.bytes), ownerSig: toBase64(rogue.ownerSig) }, malloryToken)).status).toBe(200);
  });
});

describe("kt_fork", () => {
  it("honest server: the fork flag changes nothing", async () => {
    const plain = (await get("/kt/sth")).body;
    expect((await get("/kt/sth?fork=1", { "x-krypt-fork": "1" })).body).toEqual(plain);
  });

  it("evil server: the target sees a head the witness never sees; the fork is detected", async () => {
    setKtEvil(evilFor("kt_fork", { EVIL_KT_VICTIM: "bob" }));
    const honest1 = sthFromJson((await get("/kt/sth")).body);
    const forked = sthFromJson((await get("/kt/sth", { "x-krypt-fork": "1" })).body);
    expect(forked.treeSize).toBe(honest1.treeSize + 1);
    // The fork is served consistently to its target...
    const lookup = parseLookupResponse((await get("/kt/proof?user=bob&fork=1")).body);
    expect(lookup.sth.rootHash).toEqual(forked.rootHash);
    expect((await verifyLookup({ username: "bob", response: lookup, verifySth, mldsaPk: mallory.dsa.publicKey })).ok).toBe(true);
    // ...while everyone else still gets Bob's real key.
    const real = parseLookupResponse((await get("/kt/proof?user=bob")).body);
    expect(decodeLeaf(real.leaf).mldsaPkHash).toEqual(await sha256(bob.dsa.publicKey));

    // Once the honest log reaches the same size, the two heads conflict.
    const carol = newIdentity(33);
    const reg = await signedLeaf({ op: KtOp.Register, username: "carol", keyVersion: 1, about: carol, signer: carol });
    await log.append(reg.bytes, reg.ownerSig);
    const honest2 = sthFromJson((await get("/kt/sth")).body);
    expect(honest2.treeSize).toBe(forked.treeSize);
    expect(await checkSthChain(honest2, forked, [])).toMatchObject({ ok: false, kind: "fork" });
  });
});

describe("kt_rewrite", () => {
  it("honest server: history only grows, and every head is consistent with the last", async () => {
    const first = sthFromJson((await get("/kt/sth")).body);
    const carol = newIdentity(34);
    const reg = await signedLeaf({ op: KtOp.Register, username: "carol", keyVersion: 1, about: carol, signer: carol });
    await log.append(reg.bytes, reg.ownerSig);
    const second = sthFromJson((await get("/kt/sth")).body);
    const proof = parseConsistencyResponse((await get(`/kt/consistency?from=${first.treeSize}&to=${second.treeSize}`)).body).proof;
    expect(await checkSthChain(first, second, proof)).toEqual({ ok: true });
  });

  it("evil server: a rewritten leaf breaks consistency with every earlier head", async () => {
    const carol = newIdentity(35);
    const reg = await signedLeaf({ op: KtOp.Register, username: "carol", keyVersion: 1, about: carol, signer: carol });
    await log.append(reg.bytes, reg.ownerSig);
    const before = sthFromJson((await get("/kt/sth")).body); // a client or the witness saw this

    setKtEvil(evilFor("kt_rewrite", { EVIL_KT_REWRITE_INDEX: "0" }));
    const after = sthFromJson((await get("/kt/sth")).body);
    expect(after.treeSize).toBe(before.treeSize);
    expect(after.rootHash).not.toEqual(before.rootHash);
    expect(await checkSthChain(before, after, [])).toMatchObject({ ok: false, kind: "fork" });

    // Bob's leaf now carries Mallory's key, under a valid-looking proof.
    const lookup = parseLookupResponse((await get("/kt/proof?user=bob")).body);
    expect(decodeLeaf(lookup.leaf).mldsaPkHash).toEqual(await sha256(mallory.dsa.publicKey));
    expect((await verifyLookup({ username: "bob", response: lookup, verifySth })).ok).toBe(true);

    // A client that saw size 1 before the rewrite: consistency fails.
    const old = sthFromJson((await get("/kt/proof?user=bob&size=1")).body.sth);
    const honestOld = await log.storage.sthAt(1);
    expect(old.rootHash).not.toEqual(honestOld!.rootHash);
    const proof = parseConsistencyResponse((await get(`/kt/consistency?from=1&to=${after.treeSize}`)).body).proof;
    expect(await checkSthChain(honestOld!, after, proof)).toMatchObject({ ok: false, kind: "inconsistent" });
  });
});
