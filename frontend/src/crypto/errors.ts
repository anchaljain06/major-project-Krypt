/**
 * Typed protocol errors (spec section 10). Messages never contain key material
 * or plaintext, so they are safe to log.
 */

export type DecryptErrorCode =
  | "MALFORMED"
  | "UNSUPPORTED_VERSION"
  | "NOT_FOR_ME"
  | "UNKNOWN_SESSION"
  | "SESSION_CLOSED"
  | "SESSION_SUPERSEDED"
  | "UNKNOWN_PREKEY"
  | "INIT_REPLAY"
  | "BAD_SIGNATURE"
  | "UNTRUSTED_IDENTITY"
  | "BAD_EPOCH"
  | "BAD_HEADER"
  | "DUPLICATE"
  | "STALE_EPOCH"
  | "TOO_MANY_SKIPPED"
  | "AUTH_FAILED";

/**
 * Thrown by `SessionManager.decrypt`. No state has changed when this is
 * thrown, except for SESSION_SUPERSEDED after the init authenticated: its id
 * is then tombstoned (spec 4.5) so later copies are refused.
 */
export class DecryptError extends Error {
  readonly code: DecryptErrorCode;
  constructor(code: DecryptErrorCode, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "DecryptError";
    this.code = code;
  }
}

export type HandshakeErrorCode = "NO_SIGNED_PREKEY" | "BAD_BUNDLE" | "BAD_PREKEY_SIGNATURE" | "UNTRUSTED_IDENTITY";

/** Thrown while starting a session (bundle verification, identity trust). */
export class HandshakeError extends Error {
  readonly code: HandshakeErrorCode;
  constructor(code: HandshakeErrorCode, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "HandshakeError";
    this.code = code;
  }
}
