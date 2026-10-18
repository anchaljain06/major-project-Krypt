import express, { type NextFunction, type Request, type Response } from "express";
import cors from "cors";
import helmet from "helmet";
import api from "./api.js";
import { ktPublicRouter } from "./ktRoutes.js";
import { MAX_JSON_BODY, MAX_PREKEY_JSON_BODY } from "./schemas.js";

export const ALLOWED_ORIGINS = process.env.FRONTEND_URL
  ? [process.env.FRONTEND_URL, "http://localhost:5173", "http://localhost:3000"]
  : ["http://localhost:5173", "http://localhost:3000"];

export function createApp() {
  const app = express();
  app.use(helmet());
  app.use(
    cors({
      origin: ALLOWED_ORIGINS,
      methods: ["GET", "POST"],
    }),
  );
  // A full 200-key prekey upload is ~1.65 MB of JSON; every other body is capped at 1 MB.
  app.use("/api/prekeys", express.json({ limit: MAX_PREKEY_JSON_BODY }));
  app.use(express.json({ limit: MAX_JSON_BODY }));
  app.use("/api", api);
  // Key transparency: public, unauthenticated (the witness must reach it).
  app.use("/kt", ktPublicRouter());

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

  return app;
}
