import { Router } from "express";
import { prisma } from "./db.js";
import srp from "secure-remote-password/server.js";
import { issueToken } from "./auth.js";
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

// Register a new user
router.post("/register", async (req, res) => {
  const { username, publicKey, srpSalt, srpVerifier } = req.body;

  if (!username || !publicKey || !srpSalt || !srpVerifier) {
    return res.status(400).json({ error: "Missing required registration parameters." });
  }

  try {
    const newUser = await prisma.user.create({
      data: {
        username: String(username).trim(),
        identityKeyPub: publicKey,
        srpSalt,
        srpVerifier,
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
        `[DB] Registration Error: Username '${username}' is already taken.`,
      );
    } else {
      console.error("[DB] Registration Error:", error?.message || error);
    }
    res.status(400).json({ error: "Username already exists or invalid data." });
  }
});

// SRP login step 1: generate challenge
router.post("/login/challenge", async (req, res) => {
  const { username, clientEphemeralPublic } = req.body;

  if (!username || !clientEphemeralPublic) {
    return res.status(400).json({ error: "Username and client ephemeral public key required." });
  }

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
  const { username, clientEphemeralPublic, clientSessionProof } = req.body;

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

// (Offline messages logic removed for zero-footprint architecture)

// Search users (excludes self and blocked users)
router.get("/users/search", async (req, res) => {
  const { q, current_user } = req.query;

  if (!q || typeof q !== "string") {
    return res.json([]);
  }

  try {
    // Get blocked usernames
    let blockedUsernames: string[] = [];
    if (current_user && typeof current_user === "string") {
      const blocks = await prisma.blockedUser.findMany({
        where: {
          OR: [
            { blockerUsername: current_user },
            { blockedUsername: current_user },
          ],
        },
      });
      blockedUsernames = blocks.map((b) =>
        b.blockerUsername === current_user
          ? b.blockedUsername
          : b.blockerUsername,
      );
    }

    // Build exclusion filter for self + blocked users
    const notFilter: any[] = [];
    if (current_user && typeof current_user === "string") {
      notFilter.push({ username: current_user });
    }
    blockedUsernames.forEach((u) => notFilter.push({ username: u }));

    const where: any = {
      username: { contains: q, mode: "insensitive" },
    };
    if (notFilter.length > 0) {
      where.NOT = notFilter;
    }

    const users = await prisma.user.findMany({
      where,
      select: {
        username: true,
        identityKeyPub: true,
      },
      take: 10,
    });

    res.status(200).json(users);
  } catch (err) {
    console.error("[API] Search error:", err);
    res.status(500).json({ error: "Database error during search." });
  }
});

// Send a friend request
router.post("/request/send", async (req, res) => {
  const { sender, receiver } = req.body;

  if (sender === receiver) {
    return res
      .status(400)
      .json({ error: "You cannot send a request to yourself!" });
  }

  try {
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
    console.error(err);
    res.status(500).json({ error: "Database error." });
  }
});

// Get incoming pending requests
router.get("/request/pending/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const pending = await prisma.friendRequest.findMany({
      where: {
        receiverUsername: username,
        status: "pending",
      },
      select: { senderUsername: true },
    });

    res
      .status(200)
      .json({ requests: pending.map((req) => req.senderUsername) });
  } catch (err) {
    console.error("[API] Get pending requests error:", err);
    res.status(500).json({ error: "Database error." });
  }
});

// Get outgoing sent requests
router.get("/request/sent/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const sent = await prisma.friendRequest.findMany({
      where: {
        senderUsername: username,
        status: "pending",
      },
      select: { receiverUsername: true },
    });

    res.status(200).json({ requests: sent.map((r) => r.receiverUsername) });
  } catch (err) {
    console.error("[API] Get sent requests error:", err);
    res.status(500).json({
      error: "Database error.",
      details: err instanceof Error ? err.message : String(err),
    });
  }
});

// Revoke an outgoing friend request
router.post("/request/revoke", async (req, res) => {
  const { sender, receiver } = req.body;

  try {
    await prisma.friendRequest.deleteMany({
      where: {
        senderUsername: sender,
        receiverUsername: receiver,
        status: "pending",
      },
    });

    res.status(200).json({ success: true, message: "Request revoked." });
  } catch (err) {
    console.error("[API] Revoke request error:", err);
    res.status(500).json({ error: "Database error." });
  }
});

// Accept a friend request
router.post("/request/accept", async (req, res) => {
  const { sender, receiver } = req.body;

  try {
    const request = await prisma.friendRequest.findFirst({
      where: {
        senderUsername: sender,
        receiverUsername: receiver,
        status: "pending",
      },
    });

    if (!request) {
      return res
        .status(400)
        .json({
          error: "Friend request no longer exists or has been revoked.",
        });
    }

    await prisma.friendRequest.update({
      where: { id: request.id },
      data: { status: "accepted" },
    });

    // Create or update the reverse friendship record
    const reverseExists = await prisma.friendRequest.findFirst({
      where: { senderUsername: receiver, receiverUsername: sender },
    });

    if (!reverseExists) {
      await prisma.friendRequest.create({
        data: {
          senderUsername: receiver,
          receiverUsername: sender,
          status: "accepted",
        },
      });
    } else {
      await prisma.friendRequest.updateMany({
        where: { senderUsername: receiver, receiverUsername: sender },
        data: { status: "accepted" },
      });
    }

    res
      .status(200)
      .json({ success: true, message: "Friend request accepted!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error." });
  }
});

// Reject a friend request
router.post("/request/reject", async (req, res) => {
  const { sender, receiver } = req.body;

  try {
    await prisma.friendRequest.updateMany({
      where: {
        senderUsername: sender,
        receiverUsername: receiver,
        status: "pending",
      },
      data: { status: "rejected" },
    });

    res
      .status(200)
      .json({ success: true, message: "Friend request rejected." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error." });
  }
});

// Search users by query param (excludes self + blocked)
router.get("/users/search/:query", async (req, res) => {
  const { query } = req.params;
  const { current_user } = req.query;

  try {
    let blockedUsernames: string[] = [];
    if (current_user && typeof current_user === "string") {
      const blocks = await prisma.blockedUser.findMany({
        where: {
          OR: [
            { blockerUsername: current_user },
            { blockedUsername: current_user },
          ],
        },
      });
      blockedUsernames = blocks.map((b) =>
        b.blockerUsername === current_user
          ? b.blockedUsername
          : b.blockerUsername,
      );
    }

    const notFilter: any[] = [];
    if (current_user && typeof current_user === "string") {
      notFilter.push({ username: current_user });
    }
    blockedUsernames.forEach((u) => notFilter.push({ username: u }));

    const where: any = {
      username: { contains: query, mode: "insensitive" },
    };
    if (notFilter.length > 0) {
      where.NOT = notFilter;
    }

    const users = await prisma.user.findMany({
      where,
      select: { username: true, identityKeyPub: true },
      take: 5,
    });

    res.status(200).json({ users });
  } catch (err) {
    console.error("Search API error:", err);
    res.status(500).json({ error: "Search failed." });
  }
});

// Get all accepted friends for a user
router.get("/friends/:username", async (req, res) => {
  const { username } = req.params;
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
    res.status(500).json({
      error: "Failed to fetch friends.",
      details: err instanceof Error ? err.message : String(err),
    });
  }
});

// Block a user
router.post("/block", async (req, res) => {
  const { blocker, blocked } = req.body;

  if (blocker === blocked) {
    return res.status(400).json({ error: "You cannot block yourself!" });
  }

  try {
    const existing = await prisma.blockedUser.findFirst({
      where: { blockerUsername: blocker, blockedUsername: blocked },
    });
    if (existing) {
      return res.status(400).json({ error: "User is already blocked." });
    }

    await prisma.blockedUser.create({
      data: { blockerUsername: blocker, blockedUsername: blocked },
    });

    // Remove any existing friendship between them
    await prisma.friendRequest.deleteMany({
      where: {
        OR: [
          { senderUsername: blocker, receiverUsername: blocked },
          { senderUsername: blocked, receiverUsername: blocker },
        ],
      },
    });

    res
      .status(200)
      .json({ success: true, message: `${blocked} has been blocked.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error." });
  }
});

// Unblock a user
router.post("/unblock", async (req, res) => {
  const { blocker, blocked } = req.body;

  try {
    await prisma.blockedUser.deleteMany({
      where: { blockerUsername: blocker, blockedUsername: blocked },
    });

    res
      .status(200)
      .json({ success: true, message: `${blocked} has been unblocked.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error." });
  }
});

// Get blocked users list
router.get("/blocked/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const blocked = await prisma.blockedUser.findMany({
      where: { blockerUsername: username },
      select: { blockedUsername: true },
    });

    res.status(200).json({ blocked: blocked.map((b) => b.blockedUsername) });
  } catch (err) {
    console.error("[API] Get blocked users error:", err);
    res.status(500).json({
      error: "Database error.",
      details: err instanceof Error ? err.message : String(err),
    });
  }
});

export default router;
