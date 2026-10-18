/**
 * Application layer on top of Krypt v1 envelopes.
 *
 * Socket frame (`private_message`, relayed as `receive_message`):
 *
 *   { to, type: "krypt-v1", envelope: <EnvelopeV1, spec 8.2>, attachment?: <b64url> }
 *
 * The relay stamps `from` on the frame; it must equal envelope.from. The
 * envelope's contentType ("text" | "image" | "audio" | "file") is
 * authenticated as part of the header. The plaintext inside the envelope is
 * UTF-8 JSON:
 *
 *   { v: 1, id, sentAt, text?, file?: AttachmentMeta, ctl?: FileControl, kt?: { treeSize, rootHash } }
 *
 * contentType "file" carries a large-file control message (`ctl`, spec 14);
 * the file's chunks travel separately as binary `file:chunk` frames.
 *
 * `kt` is key-transparency gossip (plan 3.3). `id` lets the receiver drop a
 * message the sender re-sent after a session race.
 */
import type { EnvelopeV1 } from "./envelope";
import { fromUtf8, utf8 } from "./encoding";
import { parseFileControl, type FileControl } from "./fileManifest";
import { MAX_SOCKET_MESSAGE_BYTES, parseAttachmentMeta, type AttachmentMeta } from "./media";

export const WIRE_TYPE = "krypt-v1";
export type ChatContentType = "text" | "image" | "audio" | "file";
export const MAX_TEXT_CHARS = 64 * 1024;
/** socket.io framing around the JSON payload (`42<ack>["private_message",...]`). */
const FRAME_OVERHEAD = 64;

export interface KtGossip {
  treeSize: number;
  rootHash: string;
}

export interface AppMessage {
  v: 1;
  id: string;
  sentAt: number;
  text?: string;
  file?: AttachmentMeta;
  ctl?: FileControl;
  kt?: KtGossip;
}

export interface WirePayload {
  to: string;
  type: typeof WIRE_TYPE;
  envelope: EnvelopeV1;
  attachment?: string;
}

export function isChatContentType(x: string): x is ChatContentType {
  return x === "text" || x === "image" || x === "audio" || x === "file";
}

export function encodeAppMessage(m: AppMessage): Uint8Array {
  return utf8(JSON.stringify(m));
}

/** Parses and checks a decrypted plaintext against the header's contentType. */
export function parseAppMessage(bytes: Uint8Array, contentType: string): AppMessage {
  if (!isChatContentType(contentType)) throw new Error(`unsupported content type "${contentType}"`);
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(fromUtf8(bytes));
  } catch {
    throw new Error("message body is not JSON");
  }
  if (!o || typeof o !== "object" || o.v !== 1 || typeof o.id !== "string" || o.id.length > 64 || typeof o.sentAt !== "number") {
    throw new Error("message body has the wrong shape");
  }
  const m: AppMessage = { v: 1, id: o.id, sentAt: o.sentAt };
  if (contentType === "text") {
    if (typeof o.text !== "string" || o.text.length > MAX_TEXT_CHARS) throw new Error("text message has no text");
    m.text = o.text;
  } else if (contentType === "file") {
    m.ctl = parseFileControl(o.ctl);
  } else {
    const file = parseAttachmentMeta(o.file);
    if (!file.mime.startsWith(`${contentType}/`)) throw new Error(`${contentType} message carries a ${file.mime} file`);
    m.file = file;
  }
  if (o.kt && typeof o.kt === "object") {
    const k = o.kt as Record<string, unknown>;
    if (typeof k.treeSize === "number" && typeof k.rootHash === "string") m.kt = { treeSize: k.treeSize, rootHash: k.rootHash };
  }
  return m;
}

export function buildWirePayload(envelope: EnvelopeV1, attachment?: string): WirePayload {
  return { to: envelope.to, type: WIRE_TYPE, envelope, ...(attachment !== undefined ? { attachment } : {}) };
}

/** Bytes the relay will see for this frame (JSON is ASCII here, so length = bytes). */
export function frameSize(p: WirePayload): number {
  return JSON.stringify(p).length + FRAME_OVERHEAD;
}

export function assertFrameFits(p: WirePayload) {
  const n = frameSize(p);
  if (n > MAX_SOCKET_MESSAGE_BYTES) {
    throw new Error(`Message is too large for the relay (${(n / (1024 * 1024)).toFixed(1)} MB > 16 MB).`);
  }
}

export type IncomingFrame =
  | { kind: "v1"; from: string; envelope: unknown; attachment?: string }
  | { kind: "malformed"; from: string };

/** Classifies a relayed frame without trusting any of it. */
export function classifyIncoming(raw: unknown): IncomingFrame {
  const o = raw as Record<string, unknown> | null;
  const from = o && typeof o === "object" && typeof o.from === "string" ? o.from : "unknown";
  if (!o || typeof o !== "object") return { kind: "malformed", from };
  if (o.envelope && typeof o.envelope === "object") {
    const env = o.envelope as Record<string, unknown>;
    if (env.from !== from) return { kind: "malformed", from };
    if (o.attachment !== undefined && typeof o.attachment !== "string") return { kind: "malformed", from };
    return { kind: "v1", from, envelope: o.envelope, attachment: o.attachment as string | undefined };
  }
  // Anything else, including v0 frames ({ ciphertext, type, eph?, sig? }), is malformed.
  return { kind: "malformed", from };
}
