import { z } from "zod";
import { SlidingWindowLimiter } from "./rateLimit.js";
import { usernameSchema } from "./schemas.js";
import type { MessagePolicy } from "./social.js";

// Binary `file:chunk` relay (spec 14.4, plan section 10).
//
// A chunk is AES-256-GCM ciphertext under a per-file key the relay never sees;
// the offer, acks and the rest of the file protocol travel as ordinary
// encrypted messages. The relay only checks routing and resource use: the
// token user is the sender, the recipient accepts messages from them, the
// frame and its counters are in range, and the sender stays within its frame,
// byte and concurrent-transfer limits. Delivery is online only: chunks are
// never stored, so an offline recipient gets OFFLINE and the sender pauses
// until the recipient asks to resume.

/** Largest chunk the clients may use (4 MiB) plus the 16-byte GCM tag. */
export const MAX_FILE_FRAME_DATA = 4 * 1024 * 1024 + 16;
export const MAX_FILE_CHUNK_INDEX = 4095;
export const MAX_FILE_NONCE_COUNTER = 0xffffffff;
export const FILE_FRAMES_PER_MINUTE = 1200;
export const FILE_BYTES_PER_MINUTE = 512 * 1024 * 1024;
export const MAX_ACTIVE_TRANSFERS = 8;
/** A transfer stops counting as active after this long without a chunk. */
export const TRANSFER_IDLE_MS = 10 * 60 * 1000;

const transferId = z
  .string()
  .length(22)
  .regex(/^[A-Za-z0-9_-]+$/)
  .refine((s) => Buffer.from(s, "base64url").toString("base64url") === s, "Expected 16 bytes.");

export const fileChunkPayload = z.strictObject({
  to: usernameSchema,
  transferId,
  index: z.number().int().min(0).max(MAX_FILE_CHUNK_INDEX),
  nonceCounter: z.number().int().min(0).max(MAX_FILE_NONCE_COUNTER),
  data: z.custom<Uint8Array>((d) => d instanceof Uint8Array, "Expected binary data."),
});

export type FileChunkError =
  | "INVALID"
  | "TOO_LARGE"
  | "BLOCKED"
  | "NOT_FRIENDS"
  | "RATE_LIMITED"
  | "TOO_MANY_TRANSFERS"
  | "OFFLINE"
  | "SERVER_ERROR";
export type FileChunkAck = { ok: true } | { ok: false; error: FileChunkError };

export interface FileRelayDeps {
  policy(from: { userId: string; username: string }, to: string): Promise<MessagePolicy>;
  /** Emit to the recipient's live socket; false if they are offline. */
  emitToUser(username: string, event: string, payload: unknown): boolean;
  now?: () => number;
}

const POLICY_ERROR: Record<Exclude<MessagePolicy, "ok">, FileChunkError> = {
  blocked: "BLOCKED",
  not_friends: "NOT_FRIENDS",
};

/** Returns the handler for one `file:chunk` frame from an authenticated sender. */
export function createFileChunkRelay(deps: FileRelayDeps) {
  const now = deps.now ?? Date.now;
  const frames = new SlidingWindowLimiter(FILE_FRAMES_PER_MINUTE, 60_000, now);
  const bytes = new SlidingWindowLimiter(FILE_BYTES_PER_MINUTE, 60_000, now);
  const active = new Map<string, Map<string, number>>();

  /** Records `id` as active for `sender`; false if that would exceed MAX_ACTIVE_TRANSFERS. */
  function touchTransfer(sender: string, id: string): boolean {
    const t = now();
    const mine = active.get(sender) ?? new Map<string, number>();
    for (const [k, last] of mine) if (t - last >= TRANSFER_IDLE_MS) mine.delete(k);
    if (!mine.has(id) && mine.size >= MAX_ACTIVE_TRANSFERS) return false;
    mine.set(id, t);
    active.set(sender, mine);
    return true;
  }

  return async function relayFileChunk(
    sender: { userId: string; username: string },
    raw: unknown,
  ): Promise<FileChunkAck> {
    const r = raw as { data?: unknown } | null;
    if (r && typeof r === "object" && r.data instanceof Uint8Array && r.data.length > MAX_FILE_FRAME_DATA) {
      return { ok: false, error: "TOO_LARGE" };
    }
    const parsed = fileChunkPayload.safeParse(raw);
    if (!parsed.success) return { ok: false, error: "INVALID" };
    const { to, data, ...rest } = parsed.data;
    if (data.length < 16) return { ok: false, error: "INVALID" };

    try {
      const policy = await deps.policy(sender, to);
      if (policy !== "ok") return { ok: false, error: POLICY_ERROR[policy] };
    } catch (err) {
      console.error("[FileRelay] Relationship check failed:", err);
      return { ok: false, error: "SERVER_ERROR" };
    }
    if (!touchTransfer(sender.username, rest.transferId)) return { ok: false, error: "TOO_MANY_TRANSFERS" };
    if (!frames.take(sender.username) || !bytes.take(sender.username, data.length)) {
      return { ok: false, error: "RATE_LIMITED" };
    }
    if (!deps.emitToUser(to, "file:chunk", { from: sender.username, ...rest, data })) {
      return { ok: false, error: "OFFLINE" };
    }
    return { ok: true };
  };
}
