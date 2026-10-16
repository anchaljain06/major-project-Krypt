import { createHmac } from "crypto";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  isActingUserMismatch,
  issueToken,
  readBearerToken,
  requireAuth,
  requireSelf,
  socketAuth,
  verifyToken,
} from "../src/auth.js";

const SECRET = "unit-test-secret";
const alice = { userId: "11111111-1111-1111-1111-111111111111", username: "Alice" };

beforeAll(() => {
  process.env.AUTH_TOKEN_SECRET = SECRET;
});

function fakeRes() {
  const res: any = { statusCode: 200, body: undefined };
  res.status = vi.fn((code: number) => {
    res.statusCode = code;
    return res;
  });
  res.json = vi.fn((body: unknown) => {
    res.body = body;
    return res;
  });
  return res;
}

describe("issueToken / verifyToken", () => {
  it("round-trips the identity", () => {
    const token = issueToken(alice, { secret: SECRET });
    expect(verifyToken(token, { secret: SECRET })).toEqual(alice);
  });

  it("uses the documented wire format", () => {
    const token = issueToken(alice, { secret: SECRET, now: 1000, ttlSeconds: 60 });
    const [first, mac] = token.split(".");
    expect(JSON.parse(Buffer.from(first!, "base64url").toString())).toEqual({
      sub: alice.userId,
      usr: "Alice",
      iat: 1000,
      exp: 1060,
    });
    const expected = createHmac("sha256", SECRET).update(first!).digest("base64url");
    expect(mac).toBe(expected);
  });

  it("rejects expired tokens", () => {
    const token = issueToken(alice, { secret: SECRET, now: 1000, ttlSeconds: 60 });
    expect(verifyToken(token, { secret: SECRET, now: 1059 })).toEqual(alice);
    expect(verifyToken(token, { secret: SECRET, now: 1060 })).toBeNull();
  });

  it("rejects a tampered payload", () => {
    const token = issueToken(alice, { secret: SECRET });
    const [, mac] = token.split(".");
    const forged = Buffer.from(
      JSON.stringify({ sub: "x", usr: "Mallory", iat: 0, exp: 9999999999 }),
    ).toString("base64url");
    expect(verifyToken(`${forged}.${mac}`, { secret: SECRET })).toBeNull();
  });

  it("rejects a tampered MAC and a wrong secret", () => {
    const token = issueToken(alice, { secret: SECRET });
    const flipped = token.slice(0, -2) + (token.endsWith("AA") ? "BB" : "AA");
    expect(verifyToken(flipped, { secret: SECRET })).toBeNull();
    expect(verifyToken(token, { secret: "other" })).toBeNull();
  });

  it("rejects garbage", () => {
    for (const bad of [undefined, null, 42, "", "a", "a.b.c", "....", "x".repeat(5000)]) {
      expect(verifyToken(bad, { secret: SECRET })).toBeNull();
    }
  });

  it("uses AUTH_TOKEN_SECRET from the environment by default", () => {
    const token = issueToken(alice);
    expect(verifyToken(token, { secret: SECRET })).toEqual(alice);
  });
});

describe("readBearerToken", () => {
  it("parses the Authorization header", () => {
    expect(readBearerToken("Bearer abc.def")).toBe("abc.def");
    expect(readBearerToken("bearer abc.def")).toBe("abc.def");
    expect(readBearerToken("Basic abc")).toBeNull();
    expect(readBearerToken(undefined)).toBeNull();
  });
});

describe("requireAuth", () => {
  it("sets req.auth and calls next for a valid token", () => {
    const req: any = { headers: { authorization: `Bearer ${issueToken(alice)}` } };
    const res = fakeRes();
    const next = vi.fn();
    requireAuth(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(req.auth).toEqual(alice);
  });

  it("returns 401 without a token", () => {
    const req: any = { headers: {} };
    const res = fakeRes();
    const next = vi.fn();
    requireAuth(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it("returns 401 for an expired token", () => {
    const token = issueToken(alice, { now: 1000, ttlSeconds: 1 });
    const req: any = { headers: { authorization: `Bearer ${token}` } };
    const res = fakeRes();
    requireAuth(req, res, vi.fn());
    expect(res.statusCode).toBe(401);
  });
});

describe("socketAuth", () => {
  it("binds the token identity to socket.data", () => {
    const socket: any = { handshake: { auth: { token: issueToken(alice) } }, data: {} };
    const next = vi.fn();
    socketAuth(socket, next);
    expect(next).toHaveBeenCalledWith();
    expect(socket.data).toEqual({ userId: alice.userId, username: "Alice" });
  });

  it("rejects the connection without a valid token", () => {
    for (const auth of [{}, { token: "nope" }, undefined]) {
      const socket: any = { handshake: { auth }, data: {} };
      const next = vi.fn();
      socketAuth(socket, next);
      expect(next).toHaveBeenCalledOnce();
      expect(next.mock.calls[0]![0]).toBeInstanceOf(Error);
      expect(socket.data.username).toBeUndefined();
    }
  });
});

describe("acting user must equal token user (BOLA rule)", () => {
  it("allows a missing or matching name, case-insensitive", () => {
    expect(isActingUserMismatch(undefined, alice)).toBe(false);
    expect(isActingUserMismatch("", alice)).toBe(false);
    expect(isActingUserMismatch("Alice", alice)).toBe(false);
    expect(isActingUserMismatch("alice", alice)).toBe(false);
    expect(isActingUserMismatch(" ALICE ", alice)).toBe(false);
  });

  it("flags a different or non-string name", () => {
    expect(isActingUserMismatch("bob", alice)).toBe(true);
    expect(isActingUserMismatch(["alice"], alice)).toBe(true);
    expect(isActingUserMismatch(1, alice)).toBe(true);
  });

  it("requireSelf returns 403 on mismatch and passes on match", () => {
    const guard = requireSelf((req) => req.params.username);
    const bad = fakeRes();
    const next = vi.fn();
    guard({ auth: alice, params: { username: "bob" } } as any, bad, next);
    expect(bad.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();

    guard({ auth: alice, params: { username: "alice" } } as any, fakeRes(), next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("requireSelf returns 401 when no auth ran", () => {
    const res = fakeRes();
    requireSelf(() => "alice")({ params: {} } as any, res, vi.fn());
    expect(res.statusCode).toBe(401);
  });
});
