import type { Server, Socket } from "socket.io";
import { prisma } from "./db.js";
import { socketAuth } from "./auth.js";
import { enqueue, flush, MAILBOX_TTL_MS, prismaMailboxStore } from "./mailbox.js";
import { PREKEYS_LOW_WATERMARK, prekeyStatus } from "./prekeys.js";
import { onlineUsers, setIo } from "./realtime.js";
import {
  acceptOrRejectBody,
  blockBody,
  firstIssue,
  privateMessagePayload,
  sendOrRevokeBody,
  socketUsernameArg,
} from "./schemas.js";
import { messagePolicy } from "./social.js";

const mailbox = prismaMailboxStore(prisma);

type Ack = (response: unknown) => void;
const asAck = (cb: unknown): Ack => (typeof cb === "function" ? (cb as Ack) : () => {});

export type RouteStatus = "delivered_online" | "queued_offline" | "mailbox_full" | "error";

/** Deliver a (validated, from-stamped) payload now, or queue it for later. */
export async function routeMessage(
  io: Server,
  sender: Socket,
  payload: Record<string, unknown> & { to: string; from: string },
): Promise<RouteStatus> {
  const targetSocketId = onlineUsers.get(payload.to);
  if (targetSocketId) {
    console.log(`[Router] Instant delivery from ${payload.from} to ${payload.to}`);
    io.to(targetSocketId).emit("receive_message", payload);
    return "delivered_online";
  }

  try {
    const result = await enqueue(mailbox, { to: payload.to, from: payload.from, payload });
    if (result === "mailbox_full") {
      sender.emit("message_failed", {
        to: payload.to,
        reason: "mailbox_full",
        error: "Recipient's offline mailbox is full.",
      });
      return "mailbox_full";
    }
    console.log(`[Router] ${payload.to} is offline. Stored in mailbox.`);
    sender.emit("message_queued", { to: payload.to, status: "queued_offline" });
    return "queued_offline";
  } catch (err) {
    console.error(`[Router] Failed to queue offline message for ${payload.to}:`, err);
    sender.emit("message_failed", {
      to: payload.to,
      reason: "server_error",
      error: "Failed to queue offline message.",
    });
    return "error";
  }
}

/**
 * Flush the mailbox, then mark the user online. A message sent while the flush
 * runs is queued (the user is not online yet), so flush once more afterwards.
 */
async function bringOnline(io: Server, socket: Socket, username: string) {
  const deliver = (payload: unknown) => {
    if (!socket.connected) return false;
    socket.emit("receive_message", payload);
    return true;
  };

  try {
    const n = await flush(mailbox, username, deliver);
    if (n > 0) console.log(`[Mailbox] Delivered ${n} queued message(s) to ${username}`);
  } catch (err) {
    console.error(`[Mailbox] Error delivering queued messages to ${username}:`, err);
  }
  if (!socket.connected) return;

  onlineUsers.set(username, socket.id);
  socket.emit("online_users", Array.from(onlineUsers.keys()));
  socket.broadcast.emit("user_connected", username);

  try {
    await flush(mailbox, username, deliver);
  } catch (err) {
    console.error(`[Mailbox] Error in post-online flush for ${username}:`, err);
  }

  // Prekey clients that went offline while their pool drained should refill now.
  try {
    const status = await prekeyStatus(socket.data.userId);
    if (status.hasSignedPrekey && status.oneTimeRemaining < PREKEYS_LOW_WATERMARK) {
      socket.emit("prekeys_low", { remaining: status.oneTimeRemaining });
    }
  } catch (err) {
    console.error(`[Prekeys] Status check failed for ${username}:`, err);
  }
}

export function registerSocketHandlers(io: Server) {
  setIo(io);
  io.use(socketAuth);

  io.on("connection", (socket) => {
    const username: string = socket.data.username;
    const userId: string = socket.data.userId;
    console.log(`[Socket] ${username} connected with ID: ${socket.id}`);

    // Handlers are attached before the async flush so nothing sent meanwhile is lost.

    // Compatibility no-op: identity comes from the token, the argument is ignored.
    socket.on("register_socket", () => {
      if (onlineUsers.get(username) === socket.id) {
        socket.emit("online_users", Array.from(onlineUsers.keys()));
      }
    });

    socket.on("disconnect", () => {
      if (onlineUsers.get(username) === socket.id) {
        onlineUsers.delete(username);
        console.log(`[Socket] ${username} disconnected.`);
        io.emit("user_disconnected", username);
      }
    });

    // Route private messages: sender is always the token user; recipient must be
    // a friend who has not blocked the sender.
    socket.on("private_message", async (raw: unknown, callback?: unknown) => {
      const ack = asAck(callback);
      const parsed = privateMessagePayload.safeParse(raw);
      if (!parsed.success) {
        const to = (raw as { to?: unknown } | null)?.to;
        const error = firstIssue(parsed.error);
        socket.emit("message_failed", {
          to: typeof to === "string" ? to : undefined,
          reason: "invalid_payload",
          error,
        });
        return ack({ success: false, reason: "invalid_payload", error });
      }
      const payload = { ...parsed.data, from: username };

      try {
        const policy = await messagePolicy({ userId, username }, payload.to);
        if (policy !== "ok") {
          const error =
            policy === "blocked"
              ? "You cannot message this user."
              : "You can only message friends.";
          socket.emit("message_failed", { to: payload.to, reason: policy, error });
          return ack({ success: false, reason: policy, error });
        }
      } catch (err) {
        console.error("[Router] Relationship check failed:", err);
        socket.emit("message_failed", {
          to: payload.to,
          reason: "server_error",
          error: "Could not deliver message.",
        });
        return ack({ success: false, reason: "server_error" });
      }

      const status = await routeMessage(io, socket, payload);
      if (status === "delivered_online" || status === "queued_offline") {
        ack({ success: true, status });
      } else {
        ack({ success: false, reason: status });
      }
    });

    // Fetch public key for a user
    socket.on("request_public_key", async (targetUsername: unknown, callback?: unknown) => {
      const ack = asAck(callback);
      const parsed = socketUsernameArg.safeParse(targetUsername);
      if (!parsed.success) return ack({ success: false, error: "Invalid username." });
      try {
        const targetUser = await prisma.user.findUnique({
          where: { username: parsed.data },
          select: { identityKeyPub: true },
        });
        if (targetUser && targetUser.identityKeyPub) {
          ack({ success: true, publicKey: targetUser.identityKeyPub });
        } else {
          ack({ success: false, error: "User not registered or missing key." });
        }
      } catch (err) {
        console.error("[Socket] DB Error fetching key:", err);
        ack({ success: false, error: "Server error fetching key." });
      }
    });

    // Friend/block notifications. The REST call already changed the DB; these only
    // tell the other user, so each one is checked against the DB before forwarding.
    const notify = async (target: string, event: string, check: () => Promise<unknown>) => {
      const targetSocketId = onlineUsers.get(target);
      if (!targetSocketId) return;
      try {
        if (await check()) io.to(targetSocketId).emit(event, username);
      } catch (err) {
        console.error(`[Socket] ${event} check failed:`, err);
      }
    };

    socket.on("send_friend_request", (data: unknown) => {
      const parsed = sendOrRevokeBody.safeParse(data);
      if (!parsed.success) return;
      const { receiver } = parsed.data;
      void notify(receiver, "receive_friend_request", () =>
        prisma.friendRequest.findFirst({
          where: { senderId: userId, receiver: { username: receiver }, status: "pending" },
          select: { id: true },
        }),
      );
    });

    socket.on("accept_friend_request", (data: unknown) => {
      const parsed = acceptOrRejectBody.safeParse(data);
      if (!parsed.success) return;
      const { sender } = parsed.data;
      void notify(sender, "request_accepted", () =>
        prisma.friendRequest.findFirst({
          where: { sender: { username: sender }, receiverId: userId, status: "accepted" },
          select: { id: true },
        }),
      );
    });

    socket.on("reject_friend_request", (data: unknown) => {
      const parsed = acceptOrRejectBody.safeParse(data);
      if (!parsed.success) return;
      const { sender } = parsed.data;
      void notify(sender, "request_rejected", () =>
        prisma.friendRequest.findFirst({
          where: { sender: { username: sender }, receiverId: userId, status: "rejected" },
          select: { id: true },
        }),
      );
    });

    socket.on("block_user", (data: unknown) => {
      const parsed = blockBody.safeParse(data);
      if (!parsed.success) return;
      const { blocked } = parsed.data;
      void notify(blocked, "user_blocked_you", () =>
        prisma.blockedUser.findFirst({
          where: { blockerId: userId, blocked: { username: blocked } },
          select: { id: true },
        }),
      );
    });

    // The request row is already gone after a revoke, so there is nothing to check;
    // the recipient just drops the sender from its pending list.
    socket.on("revoke_friend_request", (data: unknown) => {
      const parsed = sendOrRevokeBody.safeParse(data);
      if (!parsed.success) return;
      void notify(parsed.data.receiver, "request_revoked", async () => true);
    });

    void bringOnline(io, socket, username);
  });
}

export async function purgeExpiredMailbox() {
  const removed = await mailbox.purgeExpired(new Date(Date.now() - MAILBOX_TTL_MS));
  if (removed > 0) console.log(`[Mailbox] Purged ${removed} expired message(s).`);
}
