import "dotenv/config";
import express from "express";
import cors from "cors";
import { createServer } from "http";
import { Server } from "socket.io";
import api from "./api.js";
import { prisma } from "./db.js";
import helmet from "helmet";
const ALLOWED_ORIGINS = process.env.FRONTEND_URL
  ? [process.env.FRONTEND_URL, "http://localhost:5173", "http://localhost:3000"]
  : ["http://localhost:5173", "http://localhost:3000"];
const app = express();
app.use(helmet());
app.use(
  cors({
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
  }),
);
app.use(express.json());
app.use("/api", api);

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
  },
});

// Track online users: Map<Username, SocketID>
const onlineUsers = new Map<string, string>();

io.on("connection", (socket) => {
  console.log(`[+] Socket connected: ${socket.id}`);

  // Register socket and broadcast presence
  socket.on("register_socket", async (username: string) => {
    const cleanUsername = String(username).trim();
    socket.data.username = cleanUsername;
    console.log(`[Socket] ${cleanUsername} connected with ID: ${socket.id}`);
    onlineUsers.set(cleanUsername, socket.id);

    // Send full list of online users to the newly connected client
    socket.emit("online_users", Array.from(onlineUsers.keys()));

    // Broadcast status to all other active sockets
    socket.broadcast.emit("user_connected", cleanUsername);
  });

  // Handle user disconnect (O(1) direct lookup)
  socket.on("disconnect", () => {
    const username = socket.data.username;
    if (username && onlineUsers.get(username) === socket.id) {
      onlineUsers.delete(username);
      console.log(`[Socket] ${username} disconnected.`);
      io.emit("user_disconnected", username);
    } else {
      for (const [u, socketId] of onlineUsers.entries()) {
        if (socketId === socket.id) {
          onlineUsers.delete(u);
          console.log(`[Socket] ${u} disconnected.`);
          io.emit("user_disconnected", u);
          break;
        }
      }
    }
  });

  // Strict route private messages (Drop if offline, enforce authenticated sender identity)
  socket.on("private_message", async (payload) => {
    if (socket.data.username) {
      payload.from = socket.data.username;
    }
    const targetSocketId = onlineUsers.get(payload.to);

    if (targetSocketId) {
      console.log(
        `[Router] Instant delivery from ${payload.from} to ${payload.to}`,
      );
      io.to(targetSocketId).emit("receive_message", payload);
    } else {
      console.log(`[Router] ${payload.to} is offline. Dropping message.`);
      socket.emit("message_failed", {
        to: payload.to,
        error: "User is offline. Message dropped.",
      });
    }
  });

  // Fetch public key for a user
  socket.on("request_public_key", async (targetUsername: string, callback) => {
    try {
      const targetUser = await prisma.user.findUnique({
        where: { username: targetUsername },
      });

      if (targetUser && targetUser.identityKeyPub) {
        callback({ success: true, publicKey: targetUser.identityKeyPub });
      } else {
        callback({
          success: false,
          error: "User not registered or missing key.",
        });
      }
    } catch (err) {
      console.error("[Socket] DB Error fetching key:", err);
      callback({ success: false, error: "Server error fetching key." });
    }
  });

  // Forward friend request
  socket.on("send_friend_request", (data) => {
    const { sender, receiver } = data;
    const targetSocketId = onlineUsers.get(receiver);
    if (targetSocketId) {
      io.to(targetSocketId).emit("receive_friend_request", sender);
    }
  });

  // Forward friend request acceptance
  socket.on("accept_friend_request", (data) => {
    const { sender, receiver } = data;
    const senderSocketId = onlineUsers.get(sender);

    if (senderSocketId) {
      io.to(senderSocketId).emit("request_accepted", receiver);
    }
  });

  // Forward friend request rejection
  socket.on("reject_friend_request", (data) => {
    const { sender, receiver } = data;
    const senderSocketId = onlineUsers.get(sender);

    if (senderSocketId) {
      io.to(senderSocketId).emit("request_rejected", receiver);
    }
  });

  // Notify user when blocked
  socket.on("block_user", (data) => {
    const { blocker, blocked } = data;
    const blockedSocketId = onlineUsers.get(blocked);

    if (blockedSocketId) {
      io.to(blockedSocketId).emit("user_blocked_you", blocker);
    }
  });

  // Forward friend request revocation
  socket.on("revoke_friend_request", (data) => {
    const { sender, receiver } = data;
    const receiverSocketId = onlineUsers.get(receiver);

    if (receiverSocketId) {
      io.to(receiverSocketId).emit("request_revoked", sender);
    }
  });
});

async function startServer() {
  try {
    console.log("[DB] Verifying Prisma connection...");
    await prisma.$connect();
    const userCount = await prisma.user.count();
    console.log(
      `[DB] Database connected successfully. Current users: ${userCount}`,
    );

    const PORT = process.env.PORT || 3000;
    httpServer.listen(PORT, () =>
      console.log(`Secure Blind Router running on port ${PORT}`),
    );
  } catch (error) {
    console.error("[DB] CRITICAL: Failed to connect to database!", error);
    process.exit(1);
  }
}

startServer();
