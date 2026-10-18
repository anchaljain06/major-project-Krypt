import { randomBytes } from "crypto";
import type { Server } from "http";
import type { AddressInfo } from "net";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  user: { findUnique: vi.fn() },
  oneTimePrekey: { count: vi.fn(), createMany: vi.fn(), deleteMany: vi.fn() },
  signedPrekey: { findUnique: vi.fn(), upsert: vi.fn() },
  $queryRaw: vi.fn(),
  $transaction: vi.fn(),
}));
vi.mock("../src/db.js", () => ({ prisma: db }));
const emitToUser = vi.hoisted(() => vi.fn());
vi.mock("../src/realtime.js", () => ({ emitToUser, onlineUsers: new Map(), setIo: vi.fn() }));

process.env.AUTH_TOKEN_SECRET = "prekey-test-secret";
const { createApp } = await import("../src/app.js");
const { issueToken } = await import("../src/auth.js");
const { ML_DSA_87_SIGNATURE_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES } = await import(
  "../src/sizes.js"
);

const token = issueToken({ userId: "u-alice", username: "alice" });
let server: Server;
let base: string;

beforeAll(async () => {
  server = createApp().listen(0);
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
});
afterAll(() => server.close());
beforeEach(() => {
  vi.clearAllMocks();
  db.$transaction.mockImplementation(async (fn: any) => fn(db));
});

const auth = { authorization: `Bearer ${token}` };
const b64u = (n: number) => randomBytes(n).toString("base64url");
const prekey = (keyId: number) => ({
  keyId,
  publicKey: b64u(ML_KEM_1024_PUBLIC_KEY_BYTES),
  signature: b64u(ML_DSA_87_SIGNATURE_BYTES),
});
const post = (body: unknown) =>
  fetch(`${base}/prekeys`, {
    method: "POST",
    headers: { "content-type": "application/json", ...auth },
    body: JSON.stringify(body),
  });

describe("POST /prekeys", () => {
  it("requires auth", async () => {
    const res = await fetch(`${base}/prekeys`, { method: "POST" });
    expect(res.status).toBe(401);
  });

  it("stores keys for the token user only", async () => {
    db.oneTimePrekey.count.mockResolvedValue(0);
    db.signedPrekey.findUnique.mockResolvedValue({ id: "s" });
    const res = await post({ signedPrekey: prekey(1), oneTimePrekeys: [prekey(10), prekey(11)] });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true, oneTimeRemaining: 0, hasSignedPrekey: true });
    expect(db.signedPrekey.upsert.mock.calls[0]![0].where).toEqual({ userId: "u-alice" });
    const rows = db.oneTimePrekey.createMany.mock.calls[0]![0].data;
    expect(rows.map((r: any) => [r.userId, r.keyId])).toEqual([
      ["u-alice", 10],
      ["u-alice", 11],
    ]);
  });

  it("rejects bad sizes, empty uploads and over-full pools", async () => {
    expect((await post({ oneTimePrekeys: [{ ...prekey(1), signature: b64u(64) }] })).status).toBe(
      400,
    );
    expect((await post({})).status).toBe(400);
    db.oneTimePrekey.count.mockResolvedValue(999);
    expect((await post({ oneTimePrekeys: [prekey(1), prekey(2)] })).status).toBe(400);
    expect(db.oneTimePrekey.createMany).not.toHaveBeenCalled();
  });

  it("accepts a full 200-OPK batch although it exceeds the general 1 MB limit", async () => {
    db.oneTimePrekey.count.mockResolvedValue(0);
    db.signedPrekey.findUnique.mockResolvedValue(null);
    const many = Array.from({ length: 200 }, (_, i) => prekey(i));
    expect(JSON.stringify({ oneTimePrekeys: many }).length).toBeGreaterThan(1024 * 1024);
    expect((await post({ signedPrekey: prekey(1), oneTimePrekeys: many })).status).toBe(200);
  });

  it("keeps the 1 MB limit on other routes, without leaking details", async () => {
    const res = await fetch(`${base}/block`, {
      method: "POST",
      headers: { "content-type": "application/json", ...auth },
      body: JSON.stringify({ blocked: "x".repeat(1100 * 1024) }),
    });
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ error: "Request body too large." });
  });
});

describe("DELETE /prekeys/one-time", () => {
  const del = (body?: unknown, headers: Record<string, string> = auth) =>
    fetch(`${base}/prekeys/one-time`, {
      method: "DELETE",
      headers: body === undefined ? headers : { "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

  it("requires auth", async () => {
    expect((await del(undefined, {})).status).toBe(401);
    expect(db.oneTimePrekey.deleteMany).not.toHaveBeenCalled();
  });

  it("deletes all of the caller's OPKs when keyIds is omitted", async () => {
    db.oneTimePrekey.deleteMany.mockResolvedValue({ count: 7 });
    db.oneTimePrekey.count.mockResolvedValue(0);
    for (const body of [undefined, {}]) {
      const res = await del(body);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ success: true, oneTimeRemaining: 0 });
    }
    expect(db.oneTimePrekey.deleteMany.mock.calls.map((c) => c[0])).toEqual([
      { where: { userId: "u-alice" } },
      { where: { userId: "u-alice" } },
    ]);
  });

  it("deletes only the listed keyIds, scoped to the token user", async () => {
    db.oneTimePrekey.deleteMany.mockResolvedValue({ count: 2 });
    db.oneTimePrekey.count.mockResolvedValue(40);
    const res = await del({ keyIds: [3, 9] });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true, oneTimeRemaining: 40 });
    expect(db.oneTimePrekey.deleteMany.mock.calls[0]![0]).toEqual({
      where: { userId: "u-alice", keyId: { in: [3, 9] } },
    });
    expect(db.oneTimePrekey.count.mock.calls[0]![0]).toEqual({ where: { userId: "u-alice" } });
  });

  it("rejects invalid bodies without touching the database", async () => {
    for (const bad of [
      { keyIds: [] },
      { keyIds: [1, 1] },
      { keyIds: [-1] },
      { keyIds: [1.5] },
      { keyIds: ["1"] },
      { keyIds: Array.from({ length: 1001 }, (_, i) => i) },
      { keyIds: [1], userId: "u-bob" },
      [1, 2],
    ]) {
      expect((await del(bad)).status, JSON.stringify(bad).slice(0, 40)).toBe(400);
    }
    expect(db.oneTimePrekey.deleteMany).not.toHaveBeenCalled();
  });

  it("reports a database failure as 500", async () => {
    db.oneTimePrekey.deleteMany.mockRejectedValue(new Error("down"));
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await del({ keyIds: [1] });
    spy.mockRestore();
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "Database error." });
  });
});

describe("GET /prekeys/count", () => {
  it("reports the caller's pool", async () => {
    db.oneTimePrekey.count.mockResolvedValue(42);
    db.signedPrekey.findUnique.mockResolvedValue(null);
    const res = await fetch(`${base}/prekeys/count`, { headers: auth });
    expect(await res.json()).toEqual({ oneTimeRemaining: 42, hasSignedPrekey: false });
    expect(db.oneTimePrekey.count.mock.calls[0]![0]).toEqual({ where: { userId: "u-alice" } });
  });
});

describe("GET /bundle/:username", () => {
  const spk = { keyId: 3, publicKey: "spk", signature: "sig" };

  it("returns identity key, signed prekey and one claimed OPK", async () => {
    db.user.findUnique.mockResolvedValue({
      id: "u-bob",
      username: "bob",
      identityKeyPub: "IK_B",
      signedPrekey: spk,
    });
    db.$queryRaw.mockResolvedValue([{ keyId: 9, publicKey: "opk", signature: "osig" }]);
    db.oneTimePrekey.count.mockResolvedValue(50);

    const res = await fetch(`${base}/bundle/bob`, { headers: auth });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      username: "bob",
      identityKey: "IK_B",
      signedPrekey: spk,
      oneTimePrekey: { keyId: 9, publicKey: "opk", signature: "osig" },
    });
    // The claim is a single DELETE ... FOR UPDATE SKIP LOCKED ... RETURNING
    const sql = (db.$queryRaw.mock.calls[0]![0] as string[]).join("?");
    expect(sql).toMatch(/DELETE FROM "OneTimePrekey"/);
    expect(sql).toMatch(/FOR UPDATE SKIP LOCKED/);
    expect(sql).toMatch(/RETURNING/);
    expect(db.$queryRaw.mock.calls[0]![1]).toBe("u-bob");
    await vi.waitFor(() => expect(db.oneTimePrekey.count).toHaveBeenCalled());
    expect(emitToUser).not.toHaveBeenCalled();
  });

  it("returns nulls when nothing is uploaded and warns the owner when low", async () => {
    db.user.findUnique.mockResolvedValue({
      id: "u-bob",
      username: "bob",
      identityKeyPub: "IK_B",
      signedPrekey: null,
    });
    db.$queryRaw.mockResolvedValue([]);
    db.oneTimePrekey.count.mockResolvedValue(0);
    const res = await fetch(`${base}/bundle/bob`, { headers: auth });
    expect(await res.json()).toMatchObject({ signedPrekey: null, oneTimePrekey: null });
    await vi.waitFor(() =>
      expect(emitToUser).toHaveBeenCalledWith("bob", "prekeys_low", { remaining: 0 }),
    );
  });

  it("stops handing out OPKs after 10 claims per requester and target, serving the SPK only", async () => {
    db.user.findUnique.mockResolvedValue({
      id: "u-carol",
      username: "carol",
      identityKeyPub: "IK_C",
      signedPrekey: spk,
    });
    db.$queryRaw.mockResolvedValue([{ keyId: 1, publicKey: "opk", signature: "osig" }]);
    db.oneTimePrekey.count.mockResolvedValue(50);

    for (let i = 0; i < 10; i++) {
      const body = await (await fetch(`${base}/bundle/carol`, { headers: auth })).json();
      expect(body.oneTimePrekey).not.toBeNull();
    }
    expect(db.$queryRaw).toHaveBeenCalledTimes(10);
    const limited = await fetch(`${base}/bundle/carol`, { headers: auth });
    expect(limited.status).toBe(200);
    expect(await limited.json()).toEqual({
      username: "carol",
      identityKey: "IK_C",
      signedPrekey: spk,
      oneTimePrekey: null,
    });
    expect(db.$queryRaw).toHaveBeenCalledTimes(10); // nothing claimed

    // Another requester has its own quota.
    const dave = { authorization: `Bearer ${issueToken({ userId: "u-dave", username: "dave" })}` };
    expect((await (await fetch(`${base}/bundle/carol`, { headers: dave })).json()).oneTimePrekey).not.toBeNull();
  });

  it("404s for an unknown user", async () => {
    db.user.findUnique.mockResolvedValue(null);
    expect((await fetch(`${base}/bundle/nobody`, { headers: auth })).status).toBe(404);
  });
});
