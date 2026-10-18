import { Router, type Request } from "express";
import { z } from "zod";
import { prisma } from "./db.js";
import { ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES } from "./sizes.js";
import {
  KtError,
  KtLog,
  checkSubmission,
  loadLogKey,
  parseIdentityKey,
  prismaKtStorage,
  type KtView,
} from "./kt.js";
import { parseOr400, usernameSchema } from "./schemas.js";
import {
  KT_LEAF_SIZE,
  bytesEqual,
  decodeLeaf,
  fromBase64,
  hashUsername,
  hashesToJson,
  sthToJson,
  toBase64,
  type KtLeaf,
} from "./vendor/krypt-shared/index.js";

// Key transparency HTTP API (plan 2.23). Shapes are fixed by shared/src/api.ts.
//
// Public, no auth (the witness and other users' clients must reach them):
//   GET /kt/sth                        -> { treeSize, rootHash, timestamp, signature }
//   GET /kt/consistency?from=m&to=n    -> { from, to, proof }           1 <= m <= n <= latest size
//   GET /kt/proof?user=u[&size=n]      -> { sth, leafIndex, leaf, ownerSig, proof }   404 if no leaf
//   GET /kt/leaves?from=m&to=n         -> { from, to, compactRange, leaves }   at most 1000 leaves
//   GET /kt/pubkey                     -> { algorithm, publicKey, logId }
//
// Authenticated (mounted under /api, behind requireAuth):
//   POST /api/kt/register  { leaf, ownerSig, signerPk? }  -> { leafIndex }
//   GET  /api/kt/status                                   -> { hasLeaf, keyVersion }
//
// Every size a client may name is bounded by the latest published head:
// leaves appended since then stay invisible until the next head.

export const MAX_LEAVES_PER_PAGE = 1000;

// ---------- the log instance ----------

let instance: KtLog | null = null;

/** STH publication interval; KT_STH_INTERVAL_SECONDS overrides the 5-minute default (dev/e2e). */
function sthIntervalMs(env: NodeJS.ProcessEnv): number | undefined {
  const s = Number(env.KT_STH_INTERVAL_SECONDS);
  return Number.isFinite(s) && s >= 0 && env.KT_STH_INTERVAL_SECONDS?.trim() ? s * 1000 : undefined;
}

/** The process-wide log, created on first use from DATABASE_URL and KT_LOG_SK. */
export function ktLog(): KtLog {
  if (!instance) {
    const interval = sthIntervalMs(process.env);
    instance = new KtLog(
      prismaKtStorage(prisma),
      loadLogKey(),
      interval === undefined ? {} : { sthIntervalMs: interval },
    );
  }
  return instance;
}

// Hooks for the evil relay's KT attacks (evil.ts); null in normal operation.
export interface KtEvilHooks {
  /** kt_fork / kt_rewrite: the view to serve this request. */
  viewFor(req: Request): KtView;
  /** kt_rogue_leaf: /api/kt/register appends any well-formed leaf unchecked. */
  skipRegisterChecks: boolean;
  /** kt_rogue_leaf: POST /kt/evil/rogue-leaf?victim=<name>; returns the leaf index. */
  injectRogueLeaf?: (victim: string) => Promise<number>;
}
let evil: KtEvilHooks | null = null;
export function setKtEvil(hooks: KtEvilHooks | null) {
  evil = hooks;
}

// ---------- validation ----------

const uintParam = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,15})$/, "Expected a non-negative integer.")
  .transform(Number)
  .refine(Number.isSafeInteger, "Integer too large.");

const rangeQuery = z.object({ from: uintParam, to: uintParam });
const proofQuery = z.object({ user: usernameSchema, size: uintParam.optional() });

/** Standard padded base64 that decodes to exactly `n` bytes. */
const b64Bytes = (n: number) =>
  z
    .string()
    .max(Math.ceil(n / 3) * 4)
    .transform((s, ctx) => {
      try {
        const b = fromBase64(s);
        if (b.length === n) return b;
      } catch {
        // fall through
      }
      ctx.addIssue({ code: "custom", message: `Expected base64 of exactly ${n} bytes.` });
      return z.NEVER;
    });

export const ktRegisterBody = z.object({
  leaf: b64Bytes(KT_LEAF_SIZE),
  ownerSig: b64Bytes(ML_DSA_87_SIGNATURE_BYTES),
  /** The ML-DSA-87 key that made ownerSig, when it is not the stored identity key (rotation). */
  signerPk: b64Bytes(ML_DSA_87_PUBLIC_KEY_BYTES).optional(),
});

function bad(res: import("express").Response, error: string, status = 400) {
  res.status(status).json({ error });
}

// ---------- public router ----------

export function ktPublicRouter(getLog: () => KtLog = ktLog): Router {
  const router = Router();
  const view = (req: Request) => (evil ? evil.viewFor(req) : getLog().honestView());

  router.use((_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });

  router.get("/sth", async (req, res) => {
    res.json(sthToJson(await view(req).latestSth()));
  });

  router.get("/pubkey", async (_req, res) => {
    const log = getLog();
    res.json({
      algorithm: "ML-DSA-87",
      publicKey: toBase64(log.key.publicKey),
      logId: toBase64(await log.logId),
      note: "Pin this key in the frontend and witness configuration. Never trust a key fetched at runtime.",
    });
  });

  router.get("/consistency", async (req, res) => {
    const q = parseOr400(rangeQuery, req.query, res);
    if (!q) return;
    const v = view(req);
    const latest = await v.latestSth();
    if (q.from < 1 || q.from > q.to) return bad(res, "Need 1 <= from <= to.");
    if (q.to > latest.treeSize) return bad(res, `to is beyond the latest tree size ${latest.treeSize}.`);
    const proof = await (await v.log(latest.treeSize)).consistencyProof(q.from, q.to);
    res.json({ from: q.from, to: q.to, proof: hashesToJson(proof) });
  });

  router.get("/proof", async (req, res) => {
    const q = parseOr400(proofQuery, req.query, res);
    if (!q) return;
    const v = view(req);
    const latest = await v.latestSth();
    const size = q.size ?? latest.treeSize;
    if (size > latest.treeSize) return bad(res, `size is beyond the latest tree size ${latest.treeSize}.`);
    const sth = size === latest.treeSize ? latest : await v.sthAt(size);
    if (!sth) return bad(res, "size is not a published tree size.");
    const entry = size === 0 ? null : await v.latestLeafForUser(await hashUsername(q.user), size);
    if (!entry) return bad(res, "No key transparency entry for this user.", 404);
    const proof = await (await v.log(size)).inclusionProof(entry.index, size);
    res.json({
      sth: sthToJson(sth),
      leafIndex: entry.index,
      leaf: toBase64(entry.leaf),
      ownerSig: toBase64(entry.ownerSig),
      proof: hashesToJson(proof),
    });
  });

  router.get("/leaves", async (req, res) => {
    const q = parseOr400(rangeQuery, req.query, res);
    if (!q) return;
    const v = view(req);
    const latest = await v.latestSth();
    if (q.from > q.to) return bad(res, "Need from <= to.");
    if (q.to > latest.treeSize) return bad(res, `to is beyond the latest tree size ${latest.treeSize}.`);
    const to = Math.min(q.to, q.from + MAX_LEAVES_PER_PAGE);
    const [range, leaves] = await Promise.all([
      v.log(latest.treeSize).then((l) => l.compactRange(q.from)),
      v.leaves(q.from, to),
    ]);
    if (leaves.length !== to - q.from || leaves.some((l, i) => l.index !== q.from + i)) {
      throw new Error(`KT storage returned a gap in leaves [${q.from}, ${to})`);
    }
    res.json({
      from: q.from,
      to,
      compactRange: hashesToJson(range.hashes),
      leaves: leaves.map((l) => ({ index: l.index, leaf: toBase64(l.leaf), ownerSig: toBase64(l.ownerSig) })),
    });
  });

  // Evil relay only (kt_rogue_leaf); 404 in normal operation.
  router.post("/evil/rogue-leaf", async (req, res) => {
    if (!evil?.injectRogueLeaf) return bad(res, "Not found.", 404);
    const victim = usernameSchema.safeParse(req.query.victim);
    if (!victim.success) return bad(res, "victim: invalid username.");
    try {
      res.json({ leafIndex: await evil.injectRogueLeaf(victim.data) });
    } catch (err) {
      if (err instanceof KtError) return bad(res, err.message, err.status);
      throw err;
    }
  });

  return router;
}

// ---------- authenticated router ----------

export interface KtUserLookup {
  (userId: string): Promise<{ username: string; identityKeyPub: string | null } | null>;
}

const prismaUserLookup: KtUserLookup = (userId) =>
  prisma.user.findUnique({ where: { id: userId }, select: { username: true, identityKeyPub: true } });

export function ktApiRouter(
  getLog: () => KtLog = ktLog,
  findUser: KtUserLookup = prismaUserLookup,
  now: () => number = Date.now,
): Router {
  const router = Router();

  router.post("/register", async (req, res) => {
    const body = parseOr400(ktRegisterBody, req.body, res);
    if (!body) return;

    let leaf: KtLeaf;
    try {
      leaf = decodeLeaf(body.leaf);
    } catch {
      return bad(res, "Malformed KT leaf.");
    }

    const user = await findUser(req.auth!.userId);
    if (!user) return bad(res, "User not found.", 404);

    const log = getLog();
    try {
      if (evil?.skipRegisterChecks) {
        // Evil relay kt_rogue_leaf: accept anything well-formed.
        const row = await log.append(body.leaf, body.ownerSig);
        return res.status(200).json({ leafIndex: row.index });
      }

      if (!bytesEqual(leaf.userHash, await hashUsername(user.username))) {
        return bad(res, "The leaf is for a different user.", 403);
      }
      const identity = parseIdentityKey(user.identityKeyPub);
      if (!identity) return bad(res, "Your stored identity key has no ML-DSA-87 and ML-KEM-1024 key.");

      const submission = {
        leaf,
        ownerSig: body.ownerSig,
        signerPk: body.signerPk ?? identity.mldsaPk,
        identity,
      };
      const row = await log.append(body.leaf, body.ownerSig, (prev) =>
        checkSubmission(submission, prev, now()),
      );
      res.status(200).json({ leafIndex: row.index });
    } catch (err) {
      if (err instanceof KtError) return bad(res, err.message, err.status);
      throw err;
    }
  });

  router.get("/status", async (req, res) => {
    const user = await findUser(req.auth!.userId);
    if (!user) return bad(res, "User not found.", 404);
    const latest = await getLog().latestLeafForUser(await hashUsername(user.username));
    res.json({ hasLeaf: latest !== null, keyVersion: latest?.keyVersion ?? null });
  });

  return router;
}
