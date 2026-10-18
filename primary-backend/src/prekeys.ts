import { Router } from "express";
import { prisma } from "./db.js";
import { SlidingWindowLimiter } from "./rateLimit.js";
import { emitToUser } from "./realtime.js";
import { deleteOneTimePrekeysBody, parseOr400, uploadPrekeysBody, usernameSchema } from "./schemas.js";

// Prekey API (plan 1.20). Mounted behind requireAuth; unexpected errors reach
// the error handler in app.ts.
//   POST   /prekeys            upload a signed prekey and/or one-time prekeys
//   DELETE /prekeys/one-time   delete the caller's OPKs ({ keyIds? }; all if omitted)
//   GET    /prekeys/count      how many one-time prekeys the caller has left
//   GET  /bundle/:username   identity key + signed prekey + one claimed OPK

export const PREKEYS_LOW_WATERMARK = 20;
/** Upper bound on stored one-time prekeys per user (keeps the table bounded). */
export const MAX_STORED_OPKS = 1000;

export interface PublicPrekey {
  keyId: number;
  publicKey: string;
  signature: string;
}

export interface Bundle {
  username: string;
  identityKey: string | null;
  signedPrekey: PublicPrekey | null;
  oneTimePrekey: PublicPrekey | null;
}

/**
 * Atomically remove and return the oldest one-time prekey (lowest keyId within
 * an upload batch, whose rows share one createdAt).
 * SKIP LOCKED lets concurrent claims each take a different row; no row is
 * ever handed out twice.
 */
export async function claimOneTimePrekey(userId: string): Promise<PublicPrekey | null> {
  const rows = await prisma.$queryRaw<PublicPrekey[]>`
    DELETE FROM "OneTimePrekey"
    WHERE id = (
      SELECT id FROM "OneTimePrekey"
      WHERE "userId" = ${userId}
      ORDER BY "createdAt", "keyId"
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    )
    RETURNING "keyId", "publicKey", "signature"`;
  return rows[0] ?? null;
}

export async function prekeyStatus(userId: string) {
  const [oneTimeRemaining, signed] = await Promise.all([
    prisma.oneTimePrekey.count({ where: { userId } }),
    prisma.signedPrekey.findUnique({ where: { userId }, select: { id: true } }),
  ]);
  return { oneTimeRemaining, hasSignedPrekey: signed !== null };
}

/** Tell the owner to refill if they are online and running low. */
export async function warnIfLow(owner: { id: string; username: string }) {
  const remaining = await prisma.oneTimePrekey.count({ where: { userId: owner.id } });
  if (remaining < PREKEYS_LOW_WATERMARK) {
    emitToUser(owner.username, "prekeys_low", { remaining });
  }
}

/** OPK claims allowed per (requester, target) per window; beyond that, SPK only. */
export const OPK_CLAIMS_PER_TARGET = 10;
export const OPK_CLAIM_WINDOW_MS = 60 * 60 * 1000;
export const opkClaimLimiter = new SlidingWindowLimiter(OPK_CLAIMS_PER_TARGET, OPK_CLAIM_WINDOW_MS);

/**
 * Build the bundle for `username`, claiming one OPK if `mayClaim(ownerId)`
 * allows it. Returns null if no such user.
 * `keysFrom` lets the evil relay serve another user's keys under this name.
 */
export async function fetchBundle(
  username: string,
  keysFrom: string = username,
  mayClaim: (ownerId: string) => boolean = () => true,
): Promise<{ bundle: Bundle; owner: { id: string; username: string } } | null> {
  const owner = await prisma.user.findUnique({
    where: { username: keysFrom },
    select: {
      id: true,
      username: true,
      identityKeyPub: true,
      signedPrekey: { select: { keyId: true, publicKey: true, signature: true } },
    },
  });
  if (!owner) return null;
  const oneTimePrekey = mayClaim(owner.id) ? await claimOneTimePrekey(owner.id) : null;
  return {
    owner: { id: owner.id, username: owner.username },
    bundle: {
      username: keysFrom === username ? owner.username : username,
      identityKey: owner.identityKeyPub,
      signedPrekey: owner.signedPrekey ?? null,
      oneTimePrekey,
    },
  };
}

// Hook for the evil relay's swap_key attack; identity in normal operation.
let bundleKeySource: (username: string) => string = (username) => username;
export function setBundleKeySource(fn: (username: string) => string) {
  bundleKeySource = fn;
}

const router = Router();

router.post("/prekeys", async (req, res) => {
  const body = parseOr400(uploadPrekeysBody, req.body, res);
  if (!body) return;
  const userId = req.auth!.userId;
  const opks = body.oneTimePrekeys ?? [];

  if (!body.signedPrekey && opks.length === 0) {
    return res.status(400).json({ error: "Nothing to upload." });
  }

  if (opks.length > 0) {
    const stored = await prisma.oneTimePrekey.count({ where: { userId } });
    if (stored + opks.length > MAX_STORED_OPKS) {
      return res.status(400).json({
        error: `Too many one-time prekeys stored (max ${MAX_STORED_OPKS}).`,
      });
    }
  }

  await prisma.$transaction(async (tx) => {
    if (body.signedPrekey) {
      const { keyId, publicKey, signature } = body.signedPrekey;
      await tx.signedPrekey.upsert({
        where: { userId },
        create: { userId, keyId, publicKey, signature },
        update: { keyId, publicKey, signature, createdAt: new Date() },
      });
    }
    if (opks.length > 0) {
      // Re-uploading a keyId that is still stored is ignored, not an error.
      await tx.oneTimePrekey.createMany({
        data: opks.map((k) => ({ userId, ...k })),
        skipDuplicates: true,
      });
    }
  });

  res.status(200).json({ success: true, ...(await prekeyStatus(userId)) });
});

// Lets a client that lost its private halves (cleared storage) withdraw OPKs
// it can no longer use, so peers stop claiming them. Only the caller's rows.
router.delete("/prekeys/one-time", async (req, res) => {
  const body = parseOr400(deleteOneTimePrekeysBody, req.body, res);
  if (!body) return;
  const userId = req.auth!.userId;
  await prisma.oneTimePrekey.deleteMany({
    where: body.keyIds ? { userId, keyId: { in: body.keyIds } } : { userId },
  });
  const oneTimeRemaining = await prisma.oneTimePrekey.count({ where: { userId } });
  res.status(200).json({ success: true, oneTimeRemaining });
});

router.get("/prekeys/count", async (req, res) => {
  res.status(200).json(await prekeyStatus(req.auth!.userId));
});

router.get("/bundle/:username", async (req, res) => {
  const parsed = usernameSchema.safeParse(req.params.username);
  if (!parsed.success) return res.status(400).json({ error: "Invalid username." });

  const requester = req.auth!.userId;
  const result = await fetchBundle(parsed.data, bundleKeySource(parsed.data), (ownerId) =>
    opkClaimLimiter.take(`${requester}\u0000${ownerId}`),
  );
  if (!result) return res.status(404).json({ error: "User not found." });
  res.status(200).json(result.bundle);

  warnIfLow(result.owner).catch((err) =>
    console.error("[Prekeys] Low-watermark check failed:", err),
  );
});

export default router;
