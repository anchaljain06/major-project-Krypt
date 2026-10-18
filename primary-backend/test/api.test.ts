import express from "express";
import type { AddressInfo } from "net";
import type { Server } from "http";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Fake prisma: only what the routes under test touch.
const db = vi.hoisted(() => {
  const db = {
    user: { findUnique: vi.fn(), findMany: vi.fn() },
    friendRequest: {
      findMany: vi.fn(),
      findFirst: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(),
      upsert: vi.fn(),
      deleteMany: vi.fn(),
    },
    blockedUser: { findMany: vi.fn(), findFirst: vi.fn(), create: vi.fn() },
    $transaction: vi.fn(),
  };
  return db;
});
vi.mock("../src/db.js", () => ({ prisma: db }));
const emitToUser = vi.hoisted(() => vi.fn(() => true));
vi.mock("../src/realtime.js", () => ({ emitToUser, onlineUsers: new Map(), setIo: vi.fn() }));

process.env.AUTH_TOKEN_SECRET = "api-test-secret";
const { default: api } = await import("../src/api.js");
const { issueToken } = await import("../src/auth.js");

const aliceToken = issueToken({ userId: "u-alice", username: "alice" });
let server: Server;
let base: string;

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api", api);
  server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
});
afterAll(() => server.close());
beforeEach(() => vi.clearAllMocks());

const get = (path: string, token?: string) =>
  fetch(base + path, { headers: token ? { authorization: `Bearer ${token}` } : {} });
const post = (path: string, body: unknown, token?: string) =>
  fetch(base + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });

describe("authenticated REST routes", () => {
  it("returns 401 without a token", async () => {
    for (const path of ["/friends", "/blocked", "/request/pending", "/request/sent"]) {
      expect((await get(path)).status).toBe(401);
    }
    expect((await post("/request/send", { receiver: "bob" })).status).toBe(401);
  });

  it("acts only as the token user, whatever the body or URL names", async () => {
    // The old /friends/:username form no longer exists.
    expect((await get("/friends/bob", aliceToken)).status).toBe(404);

    // A body that names another acting user still acts as alice.
    db.friendRequest.findFirst.mockResolvedValue(null);
    const res = await post("/request/accept", { sender: "carol", receiver: "bob" }, aliceToken);
    expect(res.status).toBe(400); // no pending request from carol to alice
    expect(db.friendRequest.findFirst.mock.calls[0]![0].where).toEqual({
      sender: { username: "carol" },
      receiverId: "u-alice",
      status: "pending",
    });
  });

  it("serves the token user's own lists", async () => {
    db.friendRequest.findMany.mockResolvedValue([
      { senderId: "u-alice", sender: { username: "alice" }, receiver: { username: "bob" } },
      { senderId: "u-carol", sender: { username: "carol" }, receiver: { username: "alice" } },
    ]);
    const res = await get("/friends", aliceToken);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ friends: ["bob", "carol"] });
    // The query is scoped by the token's User.id.
    const where = db.friendRequest.findMany.mock.calls[0]![0].where;
    expect(where.OR).toEqual([{ senderId: "u-alice" }, { receiverId: "u-alice" }]);
  });

  it("returns 400 for a malformed body and hides DB error details", async () => {
    expect((await post("/request/send", { receiver: 5 }, aliceToken)).status).toBe(400);

    db.friendRequest.findMany.mockRejectedValue(new Error("secret table layout"));
    const res = await get("/request/sent", aliceToken);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(JSON.stringify(body)).not.toContain("secret");
    expect(body.details).toBeUndefined();
  });

  it("leaves register and login public", async () => {
    // Validation failure (400), not 401: the route is reachable without a token.
    expect((await post("/register", {})).status).toBe(400);
    expect((await post("/login/challenge", {})).status).toBe(400);
    expect((await post("/login/verify", {})).status).toBe(400);
  });
});

describe("friend and block notifications", () => {
  beforeEach(() => {
    db.$transaction.mockImplementation(async (arg: unknown) =>
      typeof arg === "function" ? (arg as (tx: typeof db) => unknown)(db) : arg,
    );
  });

  it("tells the receiver about a new request", async () => {
    db.user.findUnique.mockResolvedValue({ id: "u-bob" });
    db.blockedUser.findFirst.mockResolvedValue(null);
    db.friendRequest.findFirst.mockResolvedValue(null);
    expect((await post("/request/send", { receiver: "bob" }, aliceToken)).status).toBe(200);
    expect(emitToUser).toHaveBeenCalledWith("bob", "receive_friend_request", "alice");
  });

  it("tells the sender when their request is accepted or rejected", async () => {
    db.friendRequest.findFirst.mockResolvedValue({ id: "r1", senderId: "u-bob" });
    expect((await post("/request/accept", { sender: "bob" }, aliceToken)).status).toBe(200);
    expect(emitToUser).toHaveBeenCalledWith("bob", "request_accepted", "alice");

    db.friendRequest.updateMany.mockResolvedValue({ count: 1 });
    expect((await post("/request/reject", { sender: "carol" }, aliceToken)).status).toBe(200);
    expect(emitToUser).toHaveBeenCalledWith("carol", "request_rejected", "alice");
  });

  it("tells the receiver when a request is revoked, only if one existed", async () => {
    db.friendRequest.deleteMany.mockResolvedValue({ count: 0 });
    await post("/request/revoke", { receiver: "bob" }, aliceToken);
    expect(emitToUser).not.toHaveBeenCalled();

    db.friendRequest.deleteMany.mockResolvedValue({ count: 1 });
    await post("/request/revoke", { receiver: "bob" }, aliceToken);
    expect(emitToUser).toHaveBeenCalledWith("bob", "request_revoked", "alice");
  });

  it("tells the blocked user", async () => {
    db.user.findUnique.mockResolvedValue({ id: "u-bob" });
    db.blockedUser.findFirst.mockResolvedValue(null);
    expect((await post("/block", { blocked: "bob" }, aliceToken)).status).toBe(200);
    expect(emitToUser).toHaveBeenCalledWith("bob", "user_blocked_you", "alice");
  });

  it("sends nothing when the change fails", async () => {
    db.user.findUnique.mockResolvedValue(null);
    expect((await post("/request/send", { receiver: "ghost" }, aliceToken)).status).toBe(404);
    expect(emitToUser).not.toHaveBeenCalled();
  });
});
