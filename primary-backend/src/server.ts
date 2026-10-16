import "dotenv/config";
import express, { type NextFunction, type Request, type Response } from "express";
import cors from "cors";
import { createServer } from "http";
import { Server } from "socket.io";
import api from "./api.js";
import { prisma } from "./db.js";
import helmet from "helmet";
import { MAX_JSON_BODY, MAX_SOCKET_MESSAGE_BYTES } from "./schemas.js";
import { purgeExpiredMailbox, registerSocketHandlers } from "./sockets.js";
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
app.use(express.json({ limit: MAX_JSON_BODY }));
app.use("/api", api);

// Last-resort error handler: log server-side, never leak internals to clients.
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const status = typeof err?.status === "number" && err.status >= 400 && err.status < 500
    ? err.status
    : 500;
  if (status === 500) console.error("[HTTP] Unhandled error:", err);
  const message =
    err?.type === "entity.too.large"
      ? "Request body too large."
      : status === 500
        ? "Internal server error."
        : "Malformed request.";
  res.status(status).json({ error: message });
});

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
  },
  // Default is 1 MB; the client sends up to 10 MB audio as base64 ciphertext.
  maxHttpBufferSize: MAX_SOCKET_MESSAGE_BYTES,
});

registerSocketHandlers(io);

const MAILBOX_PURGE_INTERVAL_MS = 60 * 60 * 1000;

async function startServer() {
  try {
    console.log("[DB] Verifying Prisma connection...");
    await prisma.$connect();
    const userCount = await prisma.user.count();
    console.log(
      `[DB] Database connected successfully. Current users: ${userCount}`,
    );

    await purgeExpiredMailbox();
    setInterval(() => {
      purgeExpiredMailbox().catch((err) => console.error("[Mailbox] Purge failed:", err));
    }, MAILBOX_PURGE_INTERVAL_MS).unref();

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
