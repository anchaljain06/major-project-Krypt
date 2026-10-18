import { Router, type Request } from "express";
import { prisma } from "./db.js";
import srp from "secure-remote-password/server.js";
import { issueToken, requireAuth, requireSelf, sameUsername } from "./auth.js";
import { ktApiRouter } from "./ktRoutes.js";
import prekeys from "./prekeys.js";
import { emitToUser } from "./realtime.js";
import {
  acceptOrRejectBody,
  blockBody,
  loginChallengeBody,
  loginVerifyBody,
  parseOr400,
  registerBody,
  searchQuery,
  sendOrRevokeBody,
} from "./schemas.js";
import { invalidateRelationship } from "./social.js";
const router = Router();

// SRP login challenges.
// Decision: keep keying by username so the existing client (which sends only
// username + A to /login/verify) keeps working. A new /login/challenge for the
// same user overwrites the old one, each challenge lives 2 minutes, and it is
// single use: the first /login/verify attempt consumes it, pass or fail.
// A challenge-id scheme would stop one login from cancelling another's
// challenge, but needs a client change; today an overwrite only costs a retry.
const activeLoginChallenges = new Map<string, { ephemeralSecret: string; createdAt: number }>();
const CHALLENGE_TTL_MS = 2 * 60 * 1000;

function cleanupExpiredChallenges() {
  const now = Date.now();
  for (const [key, value] of activeLoginChallenges.entries()) {
    if (now - value.createdAt > CHALLENGE_TTL_MS) {
      activeLoginChallenges.delete(key);
    }
  }
}

/** The authenticated username. Only call after requireAuth. */
function me(req: Request): string {
  return req.auth!.username;
}

/** The authenticated User.id. Only call after requireAuth. */
function myId(req: Request): string {
  return req.auth!.userId;
}

/** User.id for a username, or null if there is no such user. */
async function findUserId(username: string): Promise<string | null> {
  const user = await prisma.user.findUnique({ where: { username }, select: { id: true } });
  return user?.id ?? null;
}

const usernameOnly = { select: { username: true } } as const;

// ===================== Public routes =====================

// Register a new user
router.post("/register", async (req, res) => {
  const body = parseOr400(registerBody, req.body, res);
  if (!body) return;

  try {
    const newUser = await prisma.user.create({
      data: {
        username: body.username,
        identityKeyPub: body.publicKey,
        srpSalt: body.srpSalt,
        srpVerifier: body.srpVerifier,
      },
    });
    res.status(200).json({
      success: true,
      message: "Zero-Knowledge Identity Created",
      token: issueToken({ userId: newUser.id, username: newUser.username }),
    });
  } catch (error: any) {
    if (error?.code === "P2002") {
      console.error(
        `[DB] Registration Error: Username '${body.username}' is already taken.`,
      );
    } else {
      console.error("[DB] Registration Error:", error?.message || error);
    }
    res.status(400).json({ error: "Username already exists or invalid data." });
  }
});

// SRP login step 1: generate challenge
router.post("/login/challenge", async (req, res) => {
  const body = parseOr400(loginChallengeBody, req.body, res);
  if (!body) return;
  const { username } = body;

  cleanupExpiredChallenges();

  try {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user || !user.srpSalt || !user.srpVerifier) {
      return res
        .status(404)
        .json({ error: "User not found or missing SRP credentials." });
    }

    const serverEphemeral = srp.generateEphemeral(user.srpVerifier);
    activeLoginChallenges.set(username, {
      ephemeralSecret: serverEphemeral.secret,
      createdAt: Date.now(),
    });

    res.status(200).json({
      salt: user.srpSalt,
      serverEphemeralPublic: serverEphemeral.public,
    });
  } catch (error) {
    console.error("[SRP] Challenge Error:", error);
    res.status(500).json({ error: "Internal server error during challenge." });
  }
});

// SRP login step 2: verify client proof
router.post("/login/verify", async (req, res) => {
  const body = parseOr400(loginVerifyBody, req.body, res);
  if (!body) return;
  const { username, clientEphemeralPublic, clientSessionProof } = body;

  cleanupExpiredChallenges();

  try {
    // Single use: consume the challenge before checking anything else.
    const challengeData = activeLoginChallenges.get(username);
    activeLoginChallenges.delete(username);
    const user = await prisma.user.findUnique({ where: { username } });

    if (!user || !challengeData) {
      return res
        .status(400)
        .json({ error: "Login session expired or invalid." });
    }

    if (Date.now() - challengeData.createdAt > CHALLENGE_TTL_MS) {
      return res.status(400).json({ error: "Login challenge has expired. Please try again." });
    }

    const serverSession = srp.deriveSession(
      challengeData.ephemeralSecret,
      clientEphemeralPublic,
      user.srpSalt,
      user.username,
      user.srpVerifier,
      clientSessionProof,
    );

    // deriveSession throws if the client proof (M1) is wrong, so reaching
    // here means the password was verified. Return M2 and a session token.
    res.status(200).json({
      success: true,
      serverProof: serverSession.proof,
      token: issueToken({ userId: user.id, username: user.username }),
    });
  } catch (error) {
    console.error("[SRP] Verification Failed.");
    res.status(401).json({ error: "Invalid password." });
  }
});

// ===================== Authenticated routes =====================
// Identity comes only from the bearer token. Body/URL usernames that name the
// acting user are kept for compatibility and must match it (else 403).

router.use(requireAuth);

// POST /prekeys, DELETE /prekeys/one-time, GET /prekeys/count, GET /bundle/:username
router.use(prekeys);

// POST /kt/register, GET /kt/status (key transparency, plan 2.21)
router.use("/kt", ktApiRouter());

const SEARCH_LIMIT = 10;

async function searchUsers(req: Request, query: string) {
  const current = myId(req);
  const blocks = await prisma.blockedUser.findMany({
    where: { OR: [{ blockerId: current }, { blockedId: current }] },
    select: { blockerId: true, blockedId: true },
  });
  const excluded = new Set<string>([current]);
  for (const b of blocks) {
    excluded.add(b.blockerId === current ? b.blockedId : b.blockerId);
  }

  return prisma.user.findMany({
    where: {
      username: { contains: query, mode: "insensitive" },
      id: { notIn: [...excluded] },
    },
    select: { username: true, identityKeyPub: true },
    take: SEARCH_LIMIT,
  });
}

// Search users (excludes self and blocked users)
router.get(
  "/users/search",
  requireSelf((req) => req.query.current_user),
  async (req, res) => {
    const query = parseOr400(searchQuery, req.query, res);
    if (!query) return;
    if (!query.q) return res.json([]);

    try {
      res.status(200).json(await searchUsers(req, query.q));
    } catch (err) {
      console.error("[API] Search error:", err);
      res.status(500).json({ error: "Database error during search." });
    }
  },
);

// Send a friend request
router.post(
  "/request/send",
  requireSelf((req) => req.body?.sender),
  async (req, res) => {
    const body = parseOr400(sendOrRevokeBody, req.body, res);
    if (!body) return;
    const senderId = myId(req);
    const { receiver } = body;

    if (sameUsername(me(req), receiver)) {
      return res
        .status(400)
        .json({ error: "You cannot send a request to yourself!" });
    }

    try {
      const receiverId = await findUserId(receiver);
      if (!receiverId) {
        return res.status(404).json({ error: "User not found." });
      }

      // Check if either user has blocked the other
      const blockExists = await prisma.blockedUser.findFirst({
        where: {
          OR: [
            { blockerId: receiverId, blockedId: senderId },
            { blockerId: senderId, blockedId: receiverId },
          ],
        },
      });
      if (blockExists) {
        return res
          .status(400)
          .json({ error: "Cannot send request to this user." });
      }

      // Check if a request already exists in either direction
      const existingRequest = await prisma.friendRequest.findFirst({
        where: {
          OR: [
            { senderId, receiverId },
            { senderId: receiverId, receiverId: senderId },
          ],
        },
      });

      if (existingRequest) {
        if (existingRequest.status === "accepted") {
          return res.status(400).json({ error: "You are already friends!" });
        }
        if (existingRequest.status === "pending") {
          return res
            .status(400)
            .json({ error: "A request already exists between you two!" });
        }
        // If rejected, allow re-sending
        if (existingRequest.status === "rejected") {
          await prisma.friendRequest.update({
            where: { id: existingRequest.id },
            data: { senderId, receiverId, status: "pending" },
          });
          emitToUser(receiver, "receive_friend_request", me(req));
          return res
            .status(200)
            .json({ success: true, message: "Request re-sent!" });
        }
      }

      await prisma.friendRequest.create({
        data: { senderId, receiverId, status: "pending" },
      });
      emitToUser(receiver, "receive_friend_request", me(req));

      res.status(200).json({ success: true, message: "Request sent!" });
    } catch (err) {
      console.error("[API] Send request error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Get incoming pending requests
router.get(
  "/request/pending/:username",
  requireSelf((req) => req.params.username),
  async (req, res) => {
    try {
      const pending = await prisma.friendRequest.findMany({
        where: { receiverId: myId(req), status: "pending" },
        select: { sender: usernameOnly },
      });

      res
        .status(200)
        .json({ requests: pending.map((r) => r.sender.username) });
    } catch (err) {
      console.error("[API] Get pending requests error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Get outgoing sent requests
router.get(
  "/request/sent/:username",
  requireSelf((req) => req.params.username),
  async (req, res) => {
    try {
      const sent = await prisma.friendRequest.findMany({
        where: { senderId: myId(req), status: "pending" },
        select: { receiver: usernameOnly },
      });

      res.status(200).json({ requests: sent.map((r) => r.receiver.username) });
    } catch (err) {
      console.error("[API] Get sent requests error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Revoke an outgoing friend request
router.post(
  "/request/revoke",
  requireSelf((req) => req.body?.sender),
  async (req, res) => {
    const body = parseOr400(sendOrRevokeBody, req.body, res);
    if (!body) return;

    try {
      const { count } = await prisma.friendRequest.deleteMany({
        where: {
          senderId: myId(req),
          receiver: { username: body.receiver },
          status: "pending",
        },
      });
      if (count > 0) emitToUser(body.receiver, "request_revoked", me(req));

      res.status(200).json({ success: true, message: "Request revoked." });
    } catch (err) {
      console.error("[API] Revoke request error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Accept a friend request (the token user is the receiver)
router.post(
  "/request/accept",
  requireSelf((req) => req.body?.receiver),
  async (req, res) => {
    const body = parseOr400(acceptOrRejectBody, req.body, res);
    if (!body) return;
    const receiverId = myId(req);

    try {
      const request = await prisma.friendRequest.findFirst({
        where: {
          sender: { username: body.sender },
          receiverId,
          status: "pending",
        },
      });

      if (!request) {
        return res.status(400).json({
          error: "Friend request no longer exists or has been revoked.",
        });
      }
      const senderId = request.senderId;

      await prisma.$transaction(async (tx) => {
        await tx.friendRequest.update({
          where: { id: request.id },
          data: { status: "accepted" },
        });

        // Create or update the reverse friendship record
        await tx.friendRequest.upsert({
          where: { senderId_receiverId: { senderId: receiverId, receiverId: senderId } },
          create: { senderId: receiverId, receiverId: senderId, status: "accepted" },
          update: { status: "accepted" },
        });
      });
      invalidateRelationship(body.sender, me(req));
      emitToUser(body.sender, "request_accepted", me(req));

      res
        .status(200)
        .json({ success: true, message: "Friend request accepted!" });
    } catch (err) {
      console.error("[API] Accept request error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Reject a friend request (the token user is the receiver)
router.post(
  "/request/reject",
  requireSelf((req) => req.body?.receiver),
  async (req, res) => {
    const body = parseOr400(acceptOrRejectBody, req.body, res);
    if (!body) return;

    try {
      const { count } = await prisma.friendRequest.updateMany({
        where: {
          sender: { username: body.sender },
          receiverId: myId(req),
          status: "pending",
        },
        data: { status: "rejected" },
      });
      if (count > 0) emitToUser(body.sender, "request_rejected", me(req));

      res
        .status(200)
        .json({ success: true, message: "Friend request rejected." });
    } catch (err) {
      console.error("[API] Reject request error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Get all accepted friends for a user
router.get(
  "/friends/:username",
  requireSelf((req) => req.params.username),
  async (req, res) => {
    const userId = myId(req);
    try {
      const friends = await prisma.friendRequest.findMany({
        where: {
          status: "accepted",
          OR: [{ senderId: userId }, { receiverId: userId }],
        },
        select: { senderId: true, sender: usernameOnly, receiver: usernameOnly },
      });

      // Extract the other person's name, deduplicated
      const friendNames = [
        ...new Set(
          friends.map((f) =>
            f.senderId === userId ? f.receiver.username : f.sender.username,
          ),
        ),
      ];

      res.status(200).json({ friends: friendNames });
    } catch (err) {
      console.error("[API] Get friends error:", err);
      res.status(500).json({ error: "Failed to fetch friends." });
    }
  },
);

// Block a user
router.post(
  "/block",
  requireSelf((req) => req.body?.blocker),
  async (req, res) => {
    const body = parseOr400(blockBody, req.body, res);
    if (!body) return;
    const blockerId = myId(req);
    const { blocked } = body;

    if (sameUsername(me(req), blocked)) {
      return res.status(400).json({ error: "You cannot block yourself!" });
    }

    try {
      const blockedId = await findUserId(blocked);
      if (!blockedId) {
        return res.status(404).json({ error: "User not found." });
      }

      const existing = await prisma.blockedUser.findFirst({
        where: { blockerId, blockedId },
      });
      if (existing) {
        return res.status(400).json({ error: "User is already blocked." });
      }

      await prisma.$transaction([
        prisma.blockedUser.create({ data: { blockerId, blockedId } }),
        // Remove any existing friendship between them
        prisma.friendRequest.deleteMany({
          where: {
            OR: [
              { senderId: blockerId, receiverId: blockedId },
              { senderId: blockedId, receiverId: blockerId },
            ],
          },
        }),
      ]);
      invalidateRelationship(me(req), blocked);
      emitToUser(blocked, "user_blocked_you", me(req));

      res
        .status(200)
        .json({ success: true, message: `${blocked} has been blocked.` });
    } catch (err) {
      console.error("[API] Block error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Unblock a user
router.post(
  "/unblock",
  requireSelf((req) => req.body?.blocker),
  async (req, res) => {
    const body = parseOr400(blockBody, req.body, res);
    if (!body) return;

    try {
      await prisma.blockedUser.deleteMany({
        where: { blockerId: myId(req), blocked: { username: body.blocked } },
      });
      invalidateRelationship(me(req), body.blocked);

      res
        .status(200)
        .json({ success: true, message: `${body.blocked} has been unblocked.` });
    } catch (err) {
      console.error("[API] Unblock error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Get blocked users list
router.get(
  "/blocked/:username",
  requireSelf((req) => req.params.username),
  async (req, res) => {
    try {
      const blocked = await prisma.blockedUser.findMany({
        where: { blockerId: myId(req) },
        select: { blocked: usernameOnly },
      });

      res.status(200).json({ blocked: blocked.map((b) => b.blocked.username) });
    } catch (err) {
      console.error("[API] Get blocked users error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

export default router;
