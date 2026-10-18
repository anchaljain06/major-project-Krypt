/**
 * Sending and receiving chat messages. Every message goes through the
 * user's SessionManager (services/protocol.ts) as a Krypt v1 envelope; there
 * is no other path. Wire format: crypto/appMessage.ts.
 *
 * Receive pipeline (one FIFO queue for all peers, so per-peer order is kept;
 * the SessionManager's lock serialises each peer's state across tabs):
 *   classify frame -> decrypt (state commits only if AES-GCM verifies)
 *   -> parse plaintext -> decrypt attachment -> store locally.
 * Nothing is written to the local message DB unless every step succeeded.
 *
 * Session races (spec 4.5, open issue 1): messages sent on a session that the
 * peer has not confirmed yet are kept in an outbox. If the next authenticated
 * message from that peer arrives on a different session, ours lost the
 * simultaneous-initiation tie-break (the peer saw SESSION_SUPERSEDED), so
 * they are re-sent on the surviving session. Receivers drop duplicates by id.
 * The outbox and the seen ids are persisted, encrypted under the store key
 * (services/messageState.ts), so a refresh loses neither.
 *
 * Large files (spec 14): control messages are ordinary v1 messages with
 * contentType "file"; chunks are binary `file:chunk` frames. Both are handled
 * by one FileTransferManager per Protocol (`filesFor`).
 */
import toast from "react-hot-toast";
import { toBase64 } from "@krypt/shared";
import {
  assertFrameFits,
  buildWirePayload,
  classifyIncoming,
  encodeAppMessage,
  parseAppMessage,
  type AppMessage,
  type ChatContentType,
} from "../crypto/appMessage";
import { fromBase64url, toBase64url } from "../crypto/encoding";
import { DecryptError, HandshakeError, type DecryptErrorCode } from "../crypto/errors";
import type { FileControl } from "../crypto/fileManifest";
import { encryptLocal } from "../crypto/localStore";
import { AttachmentError, decryptAttachment, encryptAttachment } from "../crypto/media";
import type { UserIdentityKeys } from "../crypto/mlkem";
import { db } from "./db";
import { FileTransferManager, type ChunkFrame, type ChunkSendResult } from "./fileTransfer";
import type { OutgoingItem } from "./messageState";
import { resetOneTimePrekeysAfterUnknown } from "./prekeyMaintenance";
import { appLock, protocolReady, type Protocol } from "./protocol";
import { socket } from "./socket";

/** A message as kept (encrypted) in the local Dexie store and shown in the UI. */
export interface StoredMessage {
  id?: number;
  from: string;
  to: string;
  /** Text, a data: URL for images and audio, or FileCardInfo JSON for a file transfer. */
  decryptedText: string;
  type: ChatContentType;
  timestamp: number;
  /** Application message id (v1). */
  msgId?: string;
}

/** What the chat shows for a file transfer; live status comes from the FileTransferManager. */
export interface FileCardInfo {
  transferId: string;
  name: string;
  size: number;
}

export async function storeMessage(keys: UserIdentityKeys, m: StoredMessage) {
  await db.messages.add({ payload: await encryptLocal(JSON.stringify(m), keys) });
}

// ---------------------------------------------------------------------------
// Error texts

const DECRYPT_TEXT: Record<DecryptErrorCode, (peer: string) => string> = {
  MALFORMED: (p) => `Dropped a malformed message from ${p}.`,
  UNSUPPORTED_VERSION: (p) => `A message from ${p} uses an unsupported protocol version.`,
  NOT_FOR_ME: (p) => `Dropped a message from ${p} that was addressed to someone else.`,
  UNKNOWN_SESSION: (p) =>
    `Could not decrypt a message from ${p}: this device has no matching session. Send ${p} a message to start a new one.`,
  SESSION_CLOSED: (p) => `Ignored a message from ${p} on a session that was already closed.`,
  SESSION_SUPERSEDED: (p) =>
    `${p} started a session at the same moment as you. Their message will be re-sent automatically.`,
  UNKNOWN_PREKEY: (p) => `Could not start a session with ${p}: the prekey they used is no longer on this device.`,
  INIT_REPLAY: (p) => `Rejected a replayed handshake from ${p}.`,
  BAD_SIGNATURE: (p) => `Rejected a handshake from ${p}: the signature is invalid.`,
  UNTRUSTED_IDENTITY: (p) => `Rejected a message from ${p}: their identity key is not trusted.`,
  BAD_EPOCH: (p) => `Dropped an out-of-sequence message from ${p}.`,
  BAD_HEADER: (p) => `Dropped a message from ${p} with an inconsistent header.`,
  DUPLICATE: (p) => `Ignored a duplicate message from ${p}.`,
  STALE_EPOCH: (p) => `Dropped a message from ${p} that arrived too late to decrypt.`,
  TOO_MANY_SKIPPED: (p) => `Dropped a message from ${p}: too many earlier messages are missing.`,
  AUTH_FAILED: (p) => `A message from ${p} failed authentication and was dropped (tampered or corrupted).`,
};

/** Toast for a failed decrypt. Codes that are expected noise get a neutral toast. */
export function reportDecryptError(err: unknown, peer: string) {
  if (err instanceof DecryptError) {
    const text = DECRYPT_TEXT[err.code](peer);
    if (err.code === "SESSION_SUPERSEDED" || err.code === "DUPLICATE" || err.code === "SESSION_CLOSED") {
      toast(text, { icon: "ℹ️" });
    } else {
      toast.error(text);
    }
    console.warn(`[Krypt] decrypt from ${peer} failed:`, err.message);
    return;
  }
  console.error(`[Krypt] decrypt from ${peer} failed:`, err);
  toast.error(`Could not decrypt a message from ${peer}: ${err instanceof Error ? err.message : "unknown error"}`);
}

const FAILURE_TEXT: Record<string, (to: string) => string> = {
  invalid_payload: (to) => `The relay rejected a message to ${to} as malformed.`,
  blocked: (to) => `You cannot message ${to}.`,
  not_friends: (to) => `You can only message friends; ${to} is not one.`,
  mailbox_full: (to) => `${to}'s offline mailbox is full. Try again later.`,
  server_error: (to) => `The server could not deliver your message to ${to}.`,
};

/** Text for a `message_failed` socket event. */
export function describeSendFailure(data: { to?: unknown; reason?: unknown; error?: unknown }): string {
  const to = typeof data?.to === "string" ? data.to : "the recipient";
  const reason = typeof data?.reason === "string" ? data.reason : "";
  const f = FAILURE_TEXT[reason];
  if (f) return f(to);
  return `Delivery to ${to} failed: ${typeof data?.error === "string" ? data.error : "unknown error"}`;
}

/** The relay refused the frame; it has already sent `message_failed`, which is what the user sees. */
export class RelayRejectedError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(`relay rejected the message: ${reason}`);
    this.name = "RelayRejectedError";
    this.reason = reason;
  }
}

/** Toast for a failed send (skips relay rejections, which `message_failed` already reported). */
export function reportSendError(err: unknown, peer: string) {
  if (err instanceof RelayRejectedError) return;
  if (err instanceof HandshakeError) {
    const text =
      err.code === "NO_SIGNED_PREKEY"
        ? `${peer} has not published prekeys yet. They need to log in once with this version of Krypt.`
        : err.code === "UNTRUSTED_IDENTITY"
          ? `${peer}'s identity key is not trusted. Message not sent.`
          : `${peer}'s prekey bundle failed verification (${err.code}). Message not sent.`;
    toast.error(text);
    return;
  }
  toast.error(err instanceof Error && err.message ? err.message : "Failed to send message.");
}

// ---------------------------------------------------------------------------
// Sending

type Outgoing = OutgoingItem;

function emitPrivateMessage(payload: unknown, timeoutMs: number): Promise<{ success?: boolean; reason?: string }> {
  return new Promise((resolve, reject) => {
    socket.timeout(timeoutMs).emit("private_message", payload, (err: Error | null, ack?: { success?: boolean; reason?: string }) => {
      if (err) reject(new Error("The server did not acknowledge the message. Check your connection."));
      else resolve(ack ?? {});
    });
  });
}

async function transmit(p: Protocol, peer: string, item: Outgoing): Promise<string> {
  const msg: AppMessage = { ...item.msg };
  const gossip = p.kt.gossip();
  if (gossip) msg.kt = gossip;
  else delete msg.kt;
  const env = await p.session.encrypt(peer, encodeAppMessage(msg), item.contentType);
  const payload = buildWirePayload(env, item.attachment ? toBase64url(item.attachment) : undefined);
  assertFrameFits(payload);
  const timeout = 20_000 + Math.ceil((item.attachment?.length ?? 0) / 50_000) * 1000;
  const ack = await emitPrivateMessage(payload, timeout);
  if (!ack.success) throw new RelayRejectedError(ack.reason ?? "unknown");
  return env.sessionId;
}

/** Keeps `item` for re-sending while its session is unconfirmed (persisted, survives a refresh). */
export async function track(p: Protocol, peer: string, sessionId: string, item: Outgoing) {
  const status = await p.session.getStatus(peer);
  if (!status || status.established || status.sessionId !== sessionId) {
    await p.messageState.clearOutbox(peer);
    return;
  }
  await p.messageState.appendOutbox(peer, sessionId, item);
}

export type OutgoingContent =
  | { type: "text"; text: string }
  | { type: "image" | "audio"; data: Uint8Array; mime: string };

function newId(): string {
  return toBase64url(crypto.getRandomValues(new Uint8Array(16)));
}

export function toDataUrl(data: Uint8Array, mime: string): string {
  return `data:${mime};base64,${toBase64(data)}`;
}

/** Encrypts, relays and (after the relay accepted it) stores one message. */
export async function sendChatMessage(p: Protocol, peer: string, content: OutgoingContent): Promise<void> {
  const msg: AppMessage = { v: 1, id: newId(), sentAt: Date.now() };
  const item: Outgoing = { contentType: content.type, msg };
  let display: string;
  if (content.type === "text") {
    msg.text = content.text;
    display = content.text;
  } else {
    const what = content.type === "image" ? "Image" : "Audio";
    const { meta, ciphertext } = await encryptAttachment(content.data, content.mime, what);
    msg.file = meta;
    item.attachment = ciphertext;
    display = toDataUrl(content.data, content.mime);
  }
  const sessionId = await transmit(p, peer, item);
  await track(p, peer, sessionId, item);
  await storeMessage(p.keys, { from: p.username, to: peer, decryptedText: display, type: content.type, timestamp: msg.sentAt, msgId: msg.id });
}

// ---------------------------------------------------------------------------
// Large files

/** Sends one file control message as a normal v1 message (kept for re-send like any other). */
async function sendFileControl(p: Protocol, peer: string, ctl: FileControl): Promise<void> {
  const item: Outgoing = { contentType: "file", msg: { v: 1, id: newId(), sentAt: Date.now(), ctl } };
  const sessionId = await transmit(p, peer, item);
  await track(p, peer, sessionId, item);
}

/** Relays one chunk; the relay answers { ok } or { ok: false, error }. */
function sendFileChunk(peer: string, frame: ChunkFrame): Promise<ChunkSendResult> {
  return new Promise((resolve) => {
    socket.timeout(30_000).emit("file:chunk", { to: peer, ...frame }, (err: Error | null, ack?: { ok?: boolean; error?: string }) => {
      if (err) resolve("NO_ACK");
      else resolve(ack?.ok ? "ok" : (ack?.error ?? "INVALID"));
    });
  });
}

const managers = new WeakMap<Protocol, FileTransferManager>();

/** The file-transfer manager of this Protocol. */
export function filesFor(p: Protocol): FileTransferManager {
  let m = managers.get(p);
  if (!m) {
    m = new FileTransferManager({
      self: p.username,
      store: p.files,
      lock: appLock,
      sendControl: (peer, ctl) => sendFileControl(p, peer, ctl),
      sendChunk: sendFileChunk,
    });
    managers.set(p, m);
  }
  return m;
}

/** Offers `file` to `peer` and shows it in the chat. */
export async function sendFile(p: Protocol, peer: string, file: File): Promise<void> {
  const m = await filesFor(p).offer(peer, file, file.name || "file", file.type);
  const info: FileCardInfo = { transferId: m.transferId, name: m.name, size: m.size };
  await storeMessage(p.keys, { from: p.username, to: peer, decryptedText: JSON.stringify(info), type: "file", timestamp: Date.now() });
}

/** A relayed `file:chunk` frame. */
export function onFileChunk(raw: unknown) {
  const from = (raw as { from?: unknown } | null)?.from;
  if (typeof from !== "string") return;
  void protocolReady()
    .then((p) => filesFor(p).onChunk(from, raw))
    .catch((err) => console.error("[Krypt] file chunk:", err));
}

/** After a reconnect (no peer) or when `peer` comes online: ask senders to continue. */
export function resumeFileTransfers(peer?: string) {
  void protocolReady()
    .then((p) => filesFor(p).resumeWith(peer))
    .catch((err) => console.warn("[Krypt] file resume:", err));
}

/** After an authenticated message from `peer` on `sessionId`: re-send what we sent on a session that lost. */
export async function resendAfterSessionSwitch(p: Protocol, peer: string, sessionId: string) {
  const box = await p.messageState.takeOutbox(peer);
  if (!box) return;
  if (box.sessionId === sessionId) return;
  toast(`Your session with ${peer} was replaced. Re-sending ${box.items.length} message(s).`, { icon: "🔁" });
  for (const item of box.items) {
    try {
      const sid = await transmit(p, peer, item);
      await track(p, peer, sid, item);
    } catch (err) {
      reportSendError(err, peer);
    }
  }
}

// ---------------------------------------------------------------------------
// Receiving

let queue: Promise<void> = Promise.resolve();

/** Adds a relayed frame to the FIFO receive queue. */
export function enqueueIncoming(raw: unknown) {
  queue = queue.then(() => processIncoming(raw)).catch((err) => console.error("[Krypt] receive pipeline:", err));
}

async function processIncoming(raw: unknown) {
  const p = await protocolReady();
  const frame = classifyIncoming(raw);
  if (frame.kind === "malformed") {
    toast.error(`Dropped a malformed message from ${frame.from}.`);
    return;
  }

  let result;
  try {
    result = await p.session.decrypt(frame.envelope);
  } catch (err) {
    reportDecryptError(err, frame.from);
    if (err instanceof DecryptError && err.code === "UNKNOWN_PREKEY") {
      // The server handed out a prekey this device cannot answer (lost
      // prekey store): replace our one-time prekeys. Rate-limited inside.
      void resetOneTimePrekeysAfterUnknown(p).catch((e) => console.warn("[Krypt] one-time prekey reset failed:", e));
    }
    return;
  }
  const peer = result.peer;
  await resendAfterSessionSwitch(p, peer, result.sessionId);

  let msg: AppMessage;
  try {
    msg = parseAppMessage(result.plaintext, result.contentType);
  } catch (err) {
    toast.error(`Dropped a message from ${peer}: ${(err as Error).message}.`);
    return;
  }
  // A re-sent copy (spec 4.5) of a message we already stored: drop it.
  if (await p.messageState.hasSeen(peer, msg.id)) return;

  void p.kt.checkGossip(peer, msg.kt).catch((err) => console.warn("[KT] gossip check failed:", err));

  if (msg.ctl) {
    const newOffer = await filesFor(p).onControl(peer, msg.ctl);
    if (newOffer && msg.ctl.op === "offer") {
      const { transferId, name, size } = msg.ctl.manifest;
      const info: FileCardInfo = { transferId, name, size };
      await storeMessage(p.keys, { from: peer, to: p.username, decryptedText: JSON.stringify(info), type: "file", timestamp: Date.now(), msgId: msg.id });
    }
    await p.messageState.markSeen(peer, msg.id);
    return;
  }

  let display: string;
  if (msg.file) {
    try {
      if (frame.attachment === undefined) throw new AttachmentError("the attachment is missing");
      const data = await decryptAttachment(fromBase64url(frame.attachment), msg.file);
      display = toDataUrl(data, msg.file.mime);
    } catch (err) {
      toast.error(`An attachment from ${peer} was dropped: ${(err as Error).message}.`);
      return;
    }
  } else {
    display = msg.text ?? "";
  }

  await storeMessage(p.keys, {
    from: peer,
    to: p.username,
    decryptedText: display,
    type: result.contentType as ChatContentType,
    timestamp: Date.now(),
    msgId: msg.id,
  });
  // After storing: a crash in between can at worst show a re-sent copy twice, never lose one.
  await p.messageState.markSeen(peer, msg.id);
}
