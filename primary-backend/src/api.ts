import { Router, type Request, type Response } from "express";
import type { z } from "zod";
import { prisma } from "./db.js";
import srp from "secure-remote-password/server.js";
import { issueToken, requireAuth, requireSelf, sameUsername } from "./auth.js";
import {
  acceptOrRejectBody,
  blockBody,
  firstIssue,
  loginChallengeBody,
  loginVerifyBody,
  registerBody,
  searchQuery,
  sendOrRevokeBody,
  usernameSchema,
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

/** Parse input with a zod schema; on failure send 400 and return null. */
export function parseOr400<T extends z.ZodType>(
  schema: T,
  input: unknown,
  res: Response,
): z.infer<T> | null {
  const result = schema.safeParse(input ?? {});
  if (!result.success) {
    res.status(400).json({ error: firstIssue(result.error) });
    return null;
  }
  return result.data;
}

/** The authenticated username. Only call after requireAuth. */
function me(req: Request): string {
  return req.auth!.username;
}

async function userExists(username: string): Promise<boolean> {
  const user = await prisma.user.findUnique({ where: { username }, select: { id: true } });
  return user !== null;
}

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
      serverSessionProof: serverSession.proof,
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

async function searchUsers(req: Request, query: string, take: number) {
  const current = me(req);
  const blocks = await prisma.blockedUser.findMany({
    where: {
      OR: [{ blockerUsername: current }, { blockedUsername: current }],
    },
  });
  const excluded = new Set<string>([current]);
  for (const b of blocks) {
    excluded.add(b.blockerUsername === current ? b.blockedUsername : b.blockerUsername);
  }

  return prisma.user.findMany({
    where: {
      username: { contains: query, mode: "insensitive" },
      NOT: [...excluded].map((username) => ({ username })),
    },
    select: { username: true, identityKeyPub: true },
    take,
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
      res.status(200).json(await searchUsers(req, query.q, 10));
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
    const sender = me(req);
    const { receiver } = body;

    if (sameUsername(sender, receiver)) {
      return res
        .status(400)
        .json({ error: "You cannot send a request to yourself!" });
    }

    try {
      if (!(await userExists(receiver))) {
        return res.status(404).json({ error: "User not found." });
      }

      // Check if either user has blocked the other
      const blockExists = await prisma.blockedUser.findFirst({
        where: {
          OR: [
            { blockerUsername: receiver, blockedUsername: sender },
            { blockerUsername: sender, blockedUsername: receiver },
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
            { senderUsername: sender, receiverUsername: receiver },
            { senderUsername: receiver, receiverUsername: sender },
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
            data: {
              senderUsername: sender,
              receiverUsername: receiver,
              status: "pending",
            },
          });
          return res
            .status(200)
            .json({ success: true, message: "Request re-sent!" });
        }
      }

      await prisma.friendRequest.create({
        data: {
          senderUsername: sender,
          receiverUsername: receiver,
          status: "pending",
        },
      });

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
        where: {
          receiverUsername: me(req),
          status: "pending",
        },
        select: { senderUsername: true },
      });

      res
        .status(200)
        .json({ requests: pending.map((r) => r.senderUsername) });
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
        where: {
          senderUsername: me(req),
          status: "pending",
        },
        select: { receiverUsername: true },
      });

      res.status(200).json({ requests: sent.map((r) => r.receiverUsername) });
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
      await prisma.friendRequest.deleteMany({
        where: {
          senderUsername: me(req),
          receiverUsername: body.receiver,
          status: "pending",
        },
      });

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
    const receiver = me(req);
    const { sender } = body;

    try {
      const request = await prisma.friendRequest.findFirst({
        where: {
          senderUsername: sender,
          receiverUsername: receiver,
          status: "pending",
        },
      });

      if (!request) {
        return res.status(400).json({
          error: "Friend request no longer exists or has been revoked.",
        });
      }

      await prisma.$transaction(async (tx) => {
        await tx.friendRequest.update({
          where: { id: request.id },
          data: { status: "accepted" },
        });

        // Create or update the reverse friendship record
        const reverseExists = await tx.friendRequest.findFirst({
          where: { senderUsername: receiver, receiverUsername: sender },
        });

        if (!reverseExists) {
          await tx.friendRequest.create({
            data: {
              senderUsername: receiver,
              receiverUsername: sender,
              status: "accepted",
            },
          });
        } else {
          await tx.friendRequest.updateMany({
            where: { senderUsername: receiver, receiverUsername: sender },
            data: { status: "accepted" },
          });
        }
      });
      invalidateRelationship(sender, receiver);

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
      await prisma.friendRequest.updateMany({
        where: {
          senderUsername: body.sender,
          receiverUsername: me(req),
          status: "pending",
        },
        data: { status: "rejected" },
      });

      res
        .status(200)
        .json({ success: true, message: "Friend request rejected." });
    } catch (err) {
      console.error("[API] Reject request error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

// Search users by path param (excludes self + blocked)
router.get(
  "/users/search/:query",
  requireSelf((req) => req.query.current_user),
  async (req, res) => {
    const parsed = usernameSchema.safeParse(req.params.query);
    if (!parsed.success) return res.status(200).json({ users: [] });

    try {
      res.status(200).json({ users: await searchUsers(req, parsed.data, 5) });
    } catch (err) {
      console.error("Search API error:", err);
      res.status(500).json({ error: "Search failed." });
    }
  },
);

// Get all accepted friends for a user
router.get(
  "/friends/:username",
  requireSelf((req) => req.params.username),
  async (req, res) => {
    const username = me(req);
    try {
      const friends = await prisma.friendRequest.findMany({
        where: {
          status: "accepted",
          OR: [{ senderUsername: username }, { receiverUsername: username }],
        },
      });

      // Extract the other person's name, deduplicated
      const friendNames = [
        ...new Set(
          friends.map((f) =>
            f.senderUsername === username ? f.receiverUsername : f.senderUsername,
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
    const blocker = me(req);
    const { blocked } = body;

    if (sameUsername(blocker, blocked)) {
      return res.status(400).json({ error: "You cannot block yourself!" });
    }

    try {
      if (!(await userExists(blocked))) {
        return res.status(404).json({ error: "User not found." });
      }

      const existing = await prisma.blockedUser.findFirst({
        where: { blockerUsername: blocker, blockedUsername: blocked },
      });
      if (existing) {
        return res.status(400).json({ error: "User is already blocked." });
      }

      await prisma.$transaction([
        prisma.blockedUser.create({
          data: { blockerUsername: blocker, blockedUsername: blocked },
        }),
        // Remove any existing friendship between them
        prisma.friendRequest.deleteMany({
          where: {
            OR: [
              { senderUsername: blocker, receiverUsername: blocked },
              { senderUsername: blocked, receiverUsername: blocker },
            ],
          },
        }),
      ]);
      invalidateRelationship(blocker, blocked);

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
    const blocker = me(req);

    try {
      await prisma.blockedUser.deleteMany({
        where: { blockerUsername: blocker, blockedUsername: body.blocked },
      });
      invalidateRelationship(blocker, body.blocked);

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
        where: { blockerUsername: me(req) },
        select: { blockedUsername: true },
      });

      res.status(200).json({ blocked: blocked.map((b) => b.blockedUsername) });
    } catch (err) {
      console.error("[API] Get blocked users error:", err);
      res.status(500).json({ error: "Database error." });
    }
  },
);

export default router;
