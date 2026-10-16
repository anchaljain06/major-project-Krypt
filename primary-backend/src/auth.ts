import { createHmac, randomBytes, timingSafeEqual } from "crypto";
import type { NextFunction, Request, Response } from "express";
import type { Socket } from "socket.io";

// Short-lived bearer tokens issued after a successful SRP login.
// Format: base64url(JSON payload) + "." + base64url(HMAC-SHA-256(secret, firstPart))
// Payload: { sub: User.id, usr: username, iat, exp } (seconds since epoch)

export interface AuthIdentity {
  userId: string;
  username: string;
}

export interface TokenPayload {
  sub: string;
  usr: string;
  iat: number;
  exp: number;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthIdentity;
    }
  }
}

const DEFAULT_TTL_SECONDS = 43200; // 12 hours

let cachedSecret: Buffer | null = null;

function getSecret(): Buffer {
  if (cachedSecret) return cachedSecret;
  const fromEnv = process.env.AUTH_TOKEN_SECRET;
  if (fromEnv && fromEnv.length > 0) {
    cachedSecret = Buffer.from(fromEnv, "utf8");
  } else {
    cachedSecret = randomBytes(32);
    console.warn(
      "[Auth] WARNING: AUTH_TOKEN_SECRET is not set. Using a random secret; all tokens become invalid when the server restarts.",
    );
  }
  return cachedSecret;
}

function getTtlSeconds(): number {
  const raw = Number(process.env.AUTH_TOKEN_TTL_SECONDS);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : DEFAULT_TTL_SECONDS;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function sign(firstPart: string, secret: Buffer | string): Buffer {
  return createHmac("sha256", secret).update(firstPart).digest();
}

export interface TokenOptions {
  secret?: Buffer | string;
  ttlSeconds?: number;
  now?: number; // seconds
}

export function issueToken(identity: AuthIdentity, opts: TokenOptions = {}): string {
  const iat = opts.now ?? nowSeconds();
  const payload: TokenPayload = {
    sub: identity.userId,
    usr: identity.username,
    iat,
    exp: iat + (opts.ttlSeconds ?? getTtlSeconds()),
  };
  const firstPart = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const mac = sign(firstPart, opts.secret ?? getSecret()).toString("base64url");
  return `${firstPart}.${mac}`;
}

/** Returns the identity in a valid, unexpired token, or null. */
export function verifyToken(
  token: unknown,
  opts: Omit<TokenOptions, "ttlSeconds"> = {},
): AuthIdentity | null {
  if (typeof token !== "string" || token.length > 4096) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [firstPart, macPart] = parts as [string, string];

  const expected = sign(firstPart, opts.secret ?? getSecret());
  const provided = Buffer.from(macPart, "base64url");
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return null;
  }

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(firstPart, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== "object") return null;
  const { sub, usr, iat, exp } = payload as Record<string, unknown>;
  if (
    typeof sub !== "string" ||
    typeof usr !== "string" ||
    typeof iat !== "number" ||
    typeof exp !== "number"
  ) {
    return null;
  }
  if (exp <= (opts.now ?? nowSeconds())) return null;
  return { userId: sub, username: usr };
}

export function readBearerToken(header: unknown): string | null {
  if (typeof header !== "string") return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match ? match[1]! : null;
}

/** Express middleware: requires `Authorization: Bearer <token>` and sets req.auth. */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const identity = verifyToken(readBearerToken(req.headers.authorization));
  if (!identity) {
    return res.status(401).json({ error: "Authentication required." });
  }
  req.auth = identity;
  next();
}

/** Socket.io middleware: requires `io(url, { auth: { token } })`. */
export function socketAuth(socket: Socket, next: (err?: Error) => void) {
  const token = (socket.handshake.auth as Record<string, unknown> | undefined)?.token;
  const identity = verifyToken(token);
  if (!identity) {
    return next(new Error("unauthorized"));
  }
  socket.data.userId = identity.userId;
  socket.data.username = identity.username;
  next();
}

/**
 * BOLA guard. A request may name "the acting user" in its body or URL for
 * backwards compatibility, but that name must match the token user
 * (case-insensitive). A missing name is fine: identity comes from the token.
 */
export function isActingUserMismatch(claimed: unknown, identity: AuthIdentity): boolean {
  if (claimed === undefined || claimed === null || claimed === "") return false;
  if (typeof claimed !== "string") return true;
  return claimed.trim().toLowerCase() !== identity.username.toLowerCase();
}

export function sameUsername(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/** Route middleware factory: 403 when the named acting user is not the token user. */
export function requireSelf(pick: (req: Request) => unknown) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({ error: "Authentication required." });
    }
    if (isActingUserMismatch(pick(req), req.auth)) {
      return res.status(403).json({ error: "Forbidden." });
    }
    next();
  };
}
