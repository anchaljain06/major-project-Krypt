import type { Response } from "express";
import { z } from "zod";

// Input validation for every REST body and socket payload.
// Anything that fails here is rejected before it touches the DB or another client.

export const MAX_USERNAME_LENGTH = 64;
// Socket.io frame cap (maxHttpBufferSize). A single private_message must fit in it.
export const MAX_SOCKET_MESSAGE_BYTES = 16 * 1024 * 1024;
// express.json body cap.
export const MAX_JSON_BODY = "1mb";
// POST /api/prekeys only: 200 OPKs of (1568 + 4627) bytes in base64url is ~1.65 MB.
export const MAX_PREKEY_JSON_BODY = "2mb";

// No control characters; trimmed; length-limited.
export const usernameSchema = z
  .string()
  .trim()
  .min(1)
  .max(MAX_USERNAME_LENGTH)
  .regex(/^[^\u0000-\u001f\u007f]+$/, "Invalid characters in username.");

const optionalUsername = usernameSchema.optional();

const hexString = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .regex(/^[0-9a-fA-F]+$/, "Expected a hex string.");

// ---------- Auth ----------

export const registerBody = z.object({
  username: usernameSchema,
  publicKey: z.string().min(1).max(64 * 1024),
  srpSalt: hexString(1024),
  srpVerifier: hexString(4096),
});

export const loginChallengeBody = z.object({
  username: usernameSchema,
  clientEphemeralPublic: hexString(4096),
});

export const loginVerifyBody = z.object({
  username: usernameSchema,
  clientEphemeralPublic: hexString(4096),
  clientSessionProof: hexString(256),
});

// ---------- Social ----------
// The acting-user field (sender / receiver / blocker) is optional: identity comes
// from the token, the field is only accepted (and checked) for compatibility.

export const sendOrRevokeBody = z.object({
  sender: optionalUsername,
  receiver: usernameSchema,
});

export const acceptOrRejectBody = z.object({
  sender: usernameSchema,
  receiver: optionalUsername,
});

export const blockBody = z.object({
  blocker: optionalUsername,
  blocked: usernameSchema,
});

export const searchQuery = z.object({
  q: z.string().max(MAX_USERNAME_LENGTH).optional(),
  current_user: optionalUsername,
});

// ---------- Prekeys ----------

export const ML_KEM_1024_PUBLIC_KEY_BYTES = 1568;
export const ML_DSA_87_SIGNATURE_BYTES = 4627;
export const MAX_OPKS_PER_REQUEST = 200;

/** Unpadded base64url string that decodes to exactly `bytes` bytes. */
export const base64urlBytes = (bytes: number) =>
  z
    .string()
    .length(Math.ceil((bytes * 4) / 3))
    .regex(/^[A-Za-z0-9_-]+$/, "Expected unpadded base64url.")
    .refine(
      (s) => {
        const decoded = Buffer.from(s, "base64url");
        return decoded.length === bytes && decoded.toString("base64url") === s;
      },
      { message: `Expected exactly ${bytes} bytes.` },
    );

export const prekeySchema = z.object({
  keyId: z.number().int().min(0).max(2_147_483_647),
  publicKey: base64urlBytes(ML_KEM_1024_PUBLIC_KEY_BYTES),
  signature: base64urlBytes(ML_DSA_87_SIGNATURE_BYTES),
});

export const uploadPrekeysBody = z
  .object({
    signedPrekey: prekeySchema.optional(),
    oneTimePrekeys: z.array(prekeySchema).max(MAX_OPKS_PER_REQUEST).optional(),
  })
  .refine(
    (b) => {
      const ids = (b.oneTimePrekeys ?? []).map((k) => k.keyId);
      return new Set(ids).size === ids.length;
    },
    { message: "Duplicate one-time prekey keyId in request." },
  );

/** Same bound as MAX_STORED_OPKS in prekeys.ts: a user never has more to delete. */
export const MAX_OPK_DELETE_IDS = 1000;

// DELETE /api/prekeys/one-time. No keyIds: delete all of the caller's OPKs.
// An empty list is refused so that "delete nothing" is never mistaken for "delete all".
export const deleteOneTimePrekeysBody = z.strictObject({
  keyIds: z
    .array(prekeySchema.shape.keyId)
    .min(1)
    .max(MAX_OPK_DELETE_IDS)
    .refine((ids) => new Set(ids).size === ids.length, { message: "Duplicate keyId in request." })
    .optional(),
});

// ---------- Socket payloads ----------

// The relay never looks inside the ciphertext; it only needs `to`. Other fields
// are passed through untouched (protocol v0 and v1 envelopes differ), but they
// must be JSON-ish and the whole frame is capped by maxHttpBufferSize.
export const privateMessagePayload = z.looseObject({
  to: usernameSchema,
  type: z.string().max(32).optional(),
});

export const socketUsernameArg = usernameSchema;

// Friend/block socket notifications reuse the REST body shapes:
// send/revoke: { sender: me, receiver }   accept/reject: { sender, receiver: me }
// block: { blocker: me, blocked }

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

/** First issue message from a zod error, safe to show to a client. */
export function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return "Invalid input.";
  const where = issue.path.length ? `${issue.path.join(".")}: ` : "";
  return `${where}${issue.message}`;
}
