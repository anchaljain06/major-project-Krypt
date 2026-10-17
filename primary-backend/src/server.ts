import "dotenv/config";
import { createServer } from "http";
import { Server } from "socket.io";
import { ALLOWED_ORIGINS, createApp } from "./app.js";
import { prisma } from "./db.js";
import { loadEvilRelay } from "./evil.js";
import { ktLog } from "./ktRoutes.js";
import { MAX_SOCKET_MESSAGE_BYTES } from "./schemas.js";
import { purgeExpiredMailbox, registerSocketHandlers } from "./sockets.js";

const app = createApp();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
  },
  // Default is 1 MB; the client sends up to 10 MB audio as base64 ciphertext.
  maxHttpBufferSize: MAX_SOCKET_MESSAGE_BYTES,
});

// Evil relay test harness; null unless EVIL_MODE is set.
registerSocketHandlers(io, loadEvilRelay());

const MAILBOX_PURGE_INTERVAL_MS = 60 * 60 * 1000;

async function startServer() {
  try {
    console.log("[DB] Verifying Prisma connection...");
    await prisma.$connect();
    const userCount = await prisma.user.count();
    console.log(
      `[DB] Database connected successfully. Current users: ${userCount}`,
    );

    // Load the KT signing key now (fails fast on a bad KT_LOG_SK) and make
    // sure a signed tree head exists.
    const sth = await ktLog().latestSth();
    console.log(`[KT] Log has a signed tree head of size ${sth.treeSize}.`);

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
