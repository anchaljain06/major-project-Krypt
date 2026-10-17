/**
 * Krypt v1 envelope (spec section 8): header type, canonical header bytes
 * (the AES-GCM AAD), the JSON wire form and the binary form.
 *
 * Parsing is deliberately strict. Every input from the network goes through
 * `parseEnvelope` / `decodeBinaryEnvelope`, which reject anything that is not
 * exactly one canonical encoding: unknown or missing keys, wrong types,
 * out-of-range numbers, non-canonical base64url and wrong byte lengths.
 */
import { EMPTY, LABELS, fromBase64url, fromUtf8, lp, readU32, toBase64url, u32, unlp, utf8 } from "./encoding";
import { DecryptError } from "./errors";
import type { InitHeader } from "./handshake";
import { MLDSA87, isKemSuite, prekeyKem, ratchetKem, type KemSuite } from "./pq";
import { isValidKeyId } from "./prekeys";

export const PROTOCOL_VERSION = 1;
export const MAX_NAME_BYTES = 64;
export const MAX_CONTENT_TYPE_BYTES = 64;
export const MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024;
const TAG_BYTES = 16;

/** Ratchet data carried by headers of epochs >= 1. */
export interface KemField {
  ct: Uint8Array;
  ek: Uint8Array;
}

export interface Header {
  v: 1;
  suite: KemSuite;
  sessionId: Uint8Array;
  from: string;
  to: string;
  contentType: string;
  epoch: number;
  n: number;
  pn: number;
  kem: KemField | null;
  init: InitHeader | null;
}

/** Parsed envelope: header plus AES-GCM body (ciphertext ‖ tag). */
export interface Envelope {
  header: Header;
  body: Uint8Array;
}

/** JSON wire form (spec 8.2). `kem` and `init` are omitted when absent. */
export interface EnvelopeV1 {
  v: 1;
  suite: KemSuite;
  sessionId: string;
  from: string;
  to: string;
  contentType: string;
  epoch: number;
  n: number;
  pn: number;
  kem?: { ct: string; ek: string };
  init?: { spkId: number; opkId: number | null; ct1: string; ct2: string | null; ek: string; sig: string };
  body: string;
}

// ---------------------------------------------------------------------------
// Canonical bytes

/**
 * header = lp(u32(1), suite, sessionId, from, to, contentType,
 *             u32(epoch), u32(n), u32(pn), kemField, initField)
 */
export function headerBytes(h: Header): Uint8Array {
  const kemField = h.kem ? lp(h.kem.ct, h.kem.ek) : EMPTY;
  const initField = h.init
    ? lp(
        u32(h.init.spkId),
        h.init.opkId === null ? EMPTY : u32(h.init.opkId),
        h.init.ct1,
        h.init.ct2 ?? EMPTY,
        h.init.ek,
        h.init.sig,
      )
    : EMPTY;
  return lp(
    u32(h.v),
    h.suite,
    h.sessionId,
    h.from,
    h.to,
    h.contentType,
    u32(h.epoch),
    u32(h.n),
    u32(h.pn),
    kemField,
    initField,
  );
}

/** AAD = lp("Krypt-AAD-v1", header). */
export function headerAad(h: Header): Uint8Array {
  return lp(LABELS.aad, headerBytes(h));
}

/** binary = lp(header, body) (spec 8.3). */
export function encodeBinaryEnvelope(env: Envelope): Uint8Array {
  return lp(headerBytes(env.header), env.body);
}

// ---------------------------------------------------------------------------
// Validation shared by both decoders

const malformed = (why: string): never => {
  throw new DecryptError("MALFORMED", why);
};

function checkName(what: string, s: unknown, maxBytes: number): string {
  if (typeof s !== "string") return malformed(`${what} is not a string`);
  const b = utf8(s);
  // Reject lone surrogates: they would encode to the same bytes as U+FFFD,
  // so two different strings could share one AAD.
  if (b.length < 1 || b.length > maxBytes || fromUtf8(b) !== s) return malformed(`${what} has a bad length or encoding`);
  return s;
}

function checkU32(what: string, x: unknown): number {
  if (typeof x !== "number" || !Number.isInteger(x) || x < 0 || x > 0xffffffff) return malformed(`${what} out of range`);
  return x;
}

function checkLen(what: string, b: Uint8Array, len: number): Uint8Array {
  if (b.length !== len) malformed(`${what} must be ${len} bytes`);
  return b;
}

/** Semantic checks on a decoded envelope (lengths depend on the suite). */
export function validateEnvelope(env: Envelope): Envelope {
  const h = env.header;
  if (h.v !== PROTOCOL_VERSION) throw new DecryptError("UNSUPPORTED_VERSION");
  if (!isKemSuite(h.suite)) malformed("unknown suite");
  const kem = ratchetKem(h.suite);
  checkLen("sessionId", h.sessionId, 32);
  checkName("from", h.from, MAX_NAME_BYTES);
  checkName("to", h.to, MAX_NAME_BYTES);
  checkName("contentType", h.contentType, MAX_CONTENT_TYPE_BYTES);
  checkU32("epoch", h.epoch);
  checkU32("n", h.n);
  checkU32("pn", h.pn);
  if (h.kem) {
    checkLen("kem.ct", h.kem.ct, kem.lengths.cipherText);
    checkLen("kem.ek", h.kem.ek, kem.lengths.publicKey);
  }
  if (h.init) {
    if (!isValidKeyId(h.init.spkId)) malformed("init.spkId");
    if (h.init.opkId !== null && !isValidKeyId(h.init.opkId)) malformed("init.opkId");
    if ((h.init.opkId === null) !== (h.init.ct2 === null)) malformed("init.opkId and init.ct2 must both be present or absent");
    checkLen("init.ct1", h.init.ct1, prekeyKem.lengths.cipherText);
    if (h.init.ct2) checkLen("init.ct2", h.init.ct2, prekeyKem.lengths.cipherText);
    checkLen("init.ek", h.init.ek, kem.lengths.publicKey);
    checkLen("init.sig", h.init.sig, MLDSA87.signature);
  }
  // Structural rules: epoch 0 is Alice's handshake chain and is the only epoch
  // that may carry `init`; it never carries ratchet data.
  if (h.init && h.epoch !== 0) malformed("init outside epoch 0");
  if (h.kem && h.epoch === 0) malformed("kem in epoch 0");
  if (env.body.length < TAG_BYTES || env.body.length > MAX_PLAINTEXT_BYTES + TAG_BYTES) malformed("body size");
  return env;
}

// ---------------------------------------------------------------------------
// JSON

const TOP_REQUIRED = ["v", "suite", "sessionId", "from", "to", "contentType", "epoch", "n", "pn", "body"];
const TOP_OPTIONAL = ["kem", "init"];

function checkKeys(what: string, o: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
  if (!o || typeof o !== "object" || Array.isArray(o)) return malformed(`${what} is not an object`);
  const rec = o as Record<string, unknown>;
  for (const k of Object.keys(rec)) {
    if (!required.includes(k) && !optional.includes(k)) malformed(`${what} has unknown key`);
  }
  for (const k of required) if (!(k in rec)) malformed(`${what} is missing ${k}`);
  return rec;
}

function b64(what: string, s: unknown): Uint8Array {
  if (typeof s !== "string") return malformed(`${what} is not a string`);
  try {
    return fromBase64url(s);
  } catch {
    return malformed(`${what} is not canonical base64url`);
  }
}

/** Parses untrusted JSON (a string or an already-parsed object) into a validated Envelope. */
export function parseEnvelope(input: unknown): Envelope {
  let obj = input;
  if (typeof input === "string") {
    try {
      obj = JSON.parse(input);
    } catch {
      malformed("not JSON");
    }
  }
  const o = checkKeys("envelope", obj, TOP_REQUIRED, TOP_OPTIONAL);
  if (o.v !== PROTOCOL_VERSION) throw new DecryptError("UNSUPPORTED_VERSION");
  if (!isKemSuite(o.suite)) malformed("unknown suite");

  let kem: KemField | null = null;
  if ("kem" in o) {
    const k = checkKeys("kem", o.kem, ["ct", "ek"]);
    kem = { ct: b64("kem.ct", k.ct), ek: b64("kem.ek", k.ek) };
  }
  let init: InitHeader | null = null;
  if ("init" in o) {
    const i = checkKeys("init", o.init, ["spkId", "opkId", "ct1", "ct2", "ek", "sig"]);
    if (!isValidKeyId(i.spkId)) malformed("init.spkId");
    if (i.opkId !== null && !isValidKeyId(i.opkId)) malformed("init.opkId");
    init = {
      spkId: i.spkId as number,
      opkId: i.opkId as number | null,
      ct1: b64("init.ct1", i.ct1),
      ct2: i.ct2 === null ? null : b64("init.ct2", i.ct2),
      ek: b64("init.ek", i.ek),
      sig: b64("init.sig", i.sig),
    };
  }
  return validateEnvelope({
    header: {
      v: PROTOCOL_VERSION,
      suite: o.suite as KemSuite,
      sessionId: b64("sessionId", o.sessionId),
      from: checkName("from", o.from, MAX_NAME_BYTES),
      to: checkName("to", o.to, MAX_NAME_BYTES),
      contentType: checkName("contentType", o.contentType, MAX_CONTENT_TYPE_BYTES),
      epoch: checkU32("epoch", o.epoch),
      n: checkU32("n", o.n),
      pn: checkU32("pn", o.pn),
      kem,
      init,
    },
    body: b64("body", o.body),
  });
}

/** Converts a (trusted, locally built) Envelope into its JSON wire form. */
export function toWire(env: Envelope): EnvelopeV1 {
  const h = env.header;
  const out: EnvelopeV1 = {
    v: 1,
    suite: h.suite,
    sessionId: toBase64url(h.sessionId),
    from: h.from,
    to: h.to,
    contentType: h.contentType,
    epoch: h.epoch,
    n: h.n,
    pn: h.pn,
    body: toBase64url(env.body),
  };
  if (h.kem) out.kem = { ct: toBase64url(h.kem.ct), ek: toBase64url(h.kem.ek) };
  if (h.init) {
    out.init = {
      spkId: h.init.spkId,
      opkId: h.init.opkId,
      ct1: toBase64url(h.init.ct1),
      ct2: h.init.ct2 === null ? null : toBase64url(h.init.ct2),
      ek: toBase64url(h.init.ek),
      sig: toBase64url(h.init.sig),
    };
  }
  return out;
}

// ---------------------------------------------------------------------------
// Binary

/** Decodes and validates the binary form lp(header, body). */
export function decodeBinaryEnvelope(bytes: Uint8Array): Envelope {
  try {
    const [hb, body] = unlp(bytes, 2);
    const f = unlp(hb, 11);
    const str = (b: Uint8Array) => fromUtf8(b);
    const suite = str(f[1]);
    if (!isKemSuite(suite)) return malformed("unknown suite");
    let kem: KemField | null = null;
    if (f[9].length > 0) {
      const [ct, ek] = unlp(f[9], 2);
      kem = { ct: ct.slice(), ek: ek.slice() };
    }
    let init: InitHeader | null = null;
    if (f[10].length > 0) {
      const [spkId, opkId, ct1, ct2, ek, sig] = unlp(f[10], 6);
      init = {
        spkId: readU32(spkId),
        opkId: opkId.length === 0 ? null : readU32(opkId),
        ct1: ct1.slice(),
        ct2: ct2.length === 0 ? null : ct2.slice(),
        ek: ek.slice(),
        sig: sig.slice(),
      };
    }
    const v = readU32(f[0]);
    if (v !== PROTOCOL_VERSION) throw new DecryptError("UNSUPPORTED_VERSION");
    return validateEnvelope({
      header: {
        v: 1,
        suite,
        sessionId: f[2].slice(),
        from: str(f[3]),
        to: str(f[4]),
        contentType: str(f[5]),
        epoch: readU32(f[6]),
        n: readU32(f[7]),
        pn: readU32(f[8]),
        kem,
        init,
      },
      body: body.slice(),
    });
  } catch (e) {
    if (e instanceof DecryptError) throw e;
    return malformed("binary envelope does not parse");
  }
}
