import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import express from "express";
import type { Server } from "http";
import type { AddressInfo } from "net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  CompactRange,
  KtOp,
  checkSthChain,
  hashLeaf,
  parseConsistencyResponse,
  parseLeavesResponse,
  parseLookupResponse,
  sthFromJson,
  toBase64,
  verifyLeafRange,
  verifyLookup,
  verifyTreeHead,
} from "../src/vendor/krypt-shared/index.js";
import { newIdentity, randomLeafBytes, signedLeaf } from "./ktHelpers.js";

vi.mock("../src/db.js", () => ({ prisma: {} }));
process.env.AUTH_TOKEN_SECRET = "kt-test-secret";
const { issueToken, requireAuth } = await import("../src/auth.js");
const { KtLog, logKeyFromSeed, memoryKtStorage } = await import("../src/kt.js");
const { ktApiRouter, ktPublicRouter, MAX_LEAVES_PER_PAGE } = await import("../src/ktRoutes.js");

const key = logKeyFromSeed(new Uint8Array(32).fill(5));
const verifySth = (m: Uint8Array, s: Uint8Array) => key.verify(m, s);
const log = new KtLog(memoryKtStorage(), key, { sthIntervalMs: 0 });

const alice = newIdentity(21);
const alice2 = newIdentity(22);
const bob = newIdentity(23);
const users = new Map([
  ["u-alice", { username: "Alice", identityKeyPub: alice.identityKeyPub }],
  ["u-bob", { username: "bob", identityKeyPub: bob.identityKeyPub }],
  ["u-legacy", { username: "legacy", identityKeyPub: toBase64(bob.kem.publicKey) }],
]);
const tokens = {
  alice: issueToken({ userId: "u-alice", username: "Alice" }),
  bob: issueToken({ userId: "u-bob", username: "bob" }),
  legacy: issueToken({ userId: "u-legacy", username: "legacy" }),
};

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
afterAll(() => server.close());

const get = async (path: string, token?: string) => {
  const r = await fetch(base + path, { headers: token ? { authorization: `Bearer ${token}` } : {} });
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
const submit = (l: { bytes: Uint8Array; ownerSig: Uint8Array }, token: string, signerPk?: Uint8Array) =>
  post("/api/kt/register", { leaf: toBase64(l.bytes), ownerSig: toBase64(l.ownerSig), ...(signerPk ? { signerPk: toBase64(signerPk) } : {}) }, token);

describe("KT endpoints", () => {
  it("GET /kt/sth returns a signed empty head before any leaf", async () => {
    const r = await get("/kt/sth");
    expect(r.status).toBe(200);
    expect(Object.keys(r.body).sort()).toEqual(["rootHash", "signature", "timestamp", "treeSize"]);
    const sth = sthFromJson(r.body);
    expect(sth.treeSize).toBe(0);
    expect(await verifyTreeHead(sth, verifySth)).toBe(true);
  });

  it("GET /kt/pubkey returns the STH key", async () => {
    const r = await get("/kt/pubkey");
    expect(r.body.algorithm).toBe("ML-DSA-87");
    expect(r.body.publicKey).toBe(toBase64(key.publicKey));
  });

  it("GET /api/kt/status and POST /api/kt/register need a token", async () => {
    expect((await get("/api/kt/status")).status).toBe(401);
    expect((await post("/api/kt/register", {})).status).toBe(401);
  });

  it("register: appends a valid leaf, refuses everything else", async () => {
    expect((await get("/api/kt/status", tokens.alice)).body).toEqual({ hasLeaf: false, keyVersion: null });

    const reg = await signedLeaf({ op: KtOp.Register, username: "alice", keyVersion: 1, about: alice, signer: alice });
    // Leaf for alice submitted by bob.
    expect((await submit(reg, tokens.bob)).status).toBe(403);
    // Malformed inputs.
    expect((await post("/api/kt/register", { leaf: "AAAA", ownerSig: toBase64(reg.ownerSig) }, tokens.alice)).status).toBe(400);
    const badTag = new Uint8Array(reg.bytes);
    badTag[0] = 0;
    expect((await submit({ bytes: badTag, ownerSig: reg.ownerSig }, tokens.alice)).body.error).toMatch(/Malformed/);
    // Legacy identity keys cannot be logged.
    const legacy = await signedLeaf({ op: KtOp.Register, username: "legacy", keyVersion: 1, about: bob, signer: bob });
    expect((await submit(legacy, tokens.legacy)).status).toBe(400);

    const ok = await submit(reg, tokens.alice);
    expect(ok).toEqual({ status: 200, body: { leafIndex: 0 } });
    expect((await submit(reg, tokens.alice)).status).toBe(409);
    expect((await get("/api/kt/status", tokens.alice)).body).toEqual({ hasLeaf: true, keyVersion: 1 });
  });

  it("rotate: signed by the previous key, once the stored identity key is the new one", async () => {
    const rot = await signedLeaf({ op: KtOp.Rotate, username: "alice", keyVersion: 2, about: alice2, signer: alice });
    // Stored identity key is still the old one: fingerprints do not match.
    expect((await submit(rot, tokens.alice, alice.dsa.publicKey)).status).toBe(400);
    users.set("u-alice", { username: "Alice", identityKeyPub: alice2.identityKeyPub });
    // Without signerPk the server would try the new key: refused.
    expect((await submit(rot, tokens.alice)).body.error).toMatch(/previous key/);
    expect((await submit(rot, tokens.alice, alice.dsa.publicKey)).body).toEqual({ leafIndex: 1 });
    expect((await get("/api/kt/status", tokens.alice)).body).toEqual({ hasLeaf: true, keyVersion: 2 });
  });

  it("GET /kt/proof serves the latest leaf with a proof clients accept", async () => {
    const reg = await signedLeaf({ op: KtOp.Register, username: "bob", keyVersion: 1, about: bob, signer: bob });
    expect((await submit(reg, tokens.bob)).status).toBe(200);

    const r = await get("/kt/proof?user=ALICE");
    expect(r.status).toBe(200);
    expect(Object.keys(r.body).sort()).toEqual(["leaf", "leafIndex", "ownerSig", "proof", "sth"]);
    const parsed = parseLookupResponse(r.body);
    expect(parsed.leafIndex).toBe(1); // the rotation, not the register
    const result = await verifyLookup({
      username: "alice",
      response: parsed,
      verifySth,
      mldsaPk: alice2.dsa.publicKey,
      mlkemPk: alice2.kem.publicKey,
    });
    expect(result).toMatchObject({ ok: true });

    const bobs = parseLookupResponse((await get("/kt/proof?user=bob")).body);
    const verifySig = (m: Uint8Array, s: Uint8Array, pk: Uint8Array) => ml_dsa87.verify(s, m, pk);
    expect(await verifyLookup({ username: "bob", response: bobs, verifySth, mldsaPk: bob.dsa.publicKey, verifySig })).toMatchObject({ ok: true });

    // Historical size: alice's register at size 1.
    const old = parseLookupResponse((await get("/kt/proof?user=alice&size=1")).body);
    expect(old.leafIndex).toBe(0);
    expect(old.sth.treeSize).toBe(1);
    expect((await verifyLookup({ username: "alice", response: old, verifySth })).ok).toBe(true);

    expect((await get("/kt/proof?user=nobody")).status).toBe(404);
    expect((await get("/kt/proof?user=alice&size=0")).status).toBe(404);
    expect((await get("/kt/proof?user=alice&size=99")).status).toBe(400);
    expect((await get("/kt/proof")).status).toBe(400);
  });

  it("GET /kt/consistency proves each head extends the previous one", async () => {
    const r = await get("/kt/consistency?from=1&to=3");
    expect(r.status).toBe(200);
    const c = parseConsistencyResponse(r.body);
    expect(c).toMatchObject({ from: 1, to: 3 });
    const old = parseLookupResponse((await get("/kt/proof?user=alice&size=1")).body).sth;
    const latest = sthFromJson((await get("/kt/sth")).body);
    expect(await checkSthChain(old, latest, c.proof)).toEqual({ ok: true });

    for (const bad of ["from=0&to=1", "from=2&to=1", "from=1&to=4", "from=a&to=1", "from=1", "from=01&to=2", "from=-1&to=2"]) {
      expect((await get(`/kt/consistency?${bad}`)).status, bad).toBe(400);
    }
    expect((await get("/kt/consistency?from=3&to=3")).body.proof).toEqual([]);
  });

  it("GET /kt/leaves pages contiguously, caps the page and authenticates", async () => {
    // Bulk-append through a second log on the same storage that never
    // publishes, so the test does not sign 1050 heads.
    const bulk = new KtLog(log.storage, key, { sthIntervalMs: Number.MAX_SAFE_INTEGER });
    for (let i = 0; i < MAX_LEAVES_PER_PAGE + 50; i++) {
      const l = randomLeafBytes();
      await bulk.append(l.bytes, l.ownerSig);
    }
    const sth = sthFromJson((await get("/kt/sth")).body);
    expect(sth.treeSize).toBe(3 + MAX_LEAVES_PER_PAGE + 50);

    const first = await get(`/kt/leaves?from=0&to=${sth.treeSize}`);
    expect(Object.keys(first.body).sort()).toEqual(["compactRange", "from", "leaves", "to"]);
    const p1 = parseLeavesResponse(first.body);
    expect(p1.to).toBe(MAX_LEAVES_PER_PAGE);
    expect(p1.compactRange).toEqual([]);

    // Second page: compact range at size 1000 is authenticated by the client
    // via the first page; here we check the last page reaches the signed root.
    const p2 = parseLeavesResponse((await get(`/kt/leaves?from=${p1.to}&to=${sth.treeSize}`)).body);
    expect(p2.to).toBe(sth.treeSize);
    const start = await CompactRange.fromHashes(p2.from, p2.compactRange);
    expect((await verifyLeafRange(start, p2.leaves, sth)).ok).toBe(true);
    // And the whole log from the empty range.
    let range = CompactRange.empty();
    for (const e of p1.leaves) range = await range.append(await hashLeaf(e.leaf));
    expect(range.hashes).toEqual(p2.compactRange);

    expect(parseLeavesResponse((await get("/kt/leaves?from=5&to=5")).body).leaves).toEqual([]);
    expect((await get(`/kt/leaves?from=0&to=${sth.treeSize + 1}`)).status).toBe(400);
    expect((await get("/kt/leaves?from=3&to=2")).status).toBe(400);
    expect((await get("/kt/leaves?from=0&to=99999999999999999")).status).toBe(400);
  });
});
