/**
 * Catalog of malicious-relay attacks for the v0/v1 attack matrix.
 *
 * Each entry drives both runners:
 *   - v1 (frontend/e2e/attacks.spec.ts, via run-v1.mjs): the backend is started
 *     with the given EVIL_MODE / EVIL_* env and the real v1 client is observed.
 *   - v0 (evil-proxy.mjs + run-v0.mjs): the same transforms are applied by a
 *     socket.io proxy in front of the untouched v0 server.
 *
 * `kt` attacks need a KT-enabled build (VITE_KT_LOG_PUBKEY pinned). They have no
 * v0 counterpart (v0 has no key transparency).
 *
 * `scenario` selects the client flow the spec runs:
 *   message   two friends exchange several messages (the attack hits traffic)
 *   handshake first contact only (swap_key: the relay serves the wrong key)
 *   kt        KT-enabled, with a victim/attacker set up for the KT attack
 *   impersonation / bola   protocol-independent socket/REST abuse (no evil mode)
 */

export const ATTACKS = [
  {
    id: "replay",
    scenario: "message",
    env: { EVIL_MODE: "replay" },
    relay: "Re-sends the previous ciphertext of a sender->recipient pair right after the next one.",
    expected: "Replay rejected (DUPLICATE); message shown once.",
  },
  {
    id: "reorder",
    scenario: "message",
    env: { EVIL_MODE: "reorder" },
    relay: "Holds one message and releases it after the following one.",
    expected: "Both messages decrypt (out-of-order within MAX_SKIP); nothing lost.",
  },
  {
    id: "drop",
    scenario: "message",
    env: { EVIL_MODE: "drop", EVIL_DROP_EVERY: "3" },
    relay: "Drops every 3rd message per pair.",
    expected: "Dropped messages never arrive (no liveness claim); the rest decrypt, no forged content.",
  },
  {
    id: "duplicate",
    scenario: "message",
    env: { EVIL_MODE: "duplicate" },
    relay: "Delivers every message twice.",
    expected: "The duplicate is rejected (DUPLICATE) or de-duped by message id; shown once.",
  },
  {
    id: "tamper",
    scenario: "message",
    env: { EVIL_MODE: "tamper" },
    relay: "Flips one bit in one base64 field of the ciphertext.",
    expected: "AES-GCM fails: AUTH_FAILED, message dropped, session intact.",
  },
  {
    id: "flip_type",
    scenario: "message",
    env: { EVIL_MODE: "flip_type" },
    relay: "Sets the outer, unauthenticated payload.type to \"image\".",
    expected: "Ignored: v1 takes the content type from the authenticated header, so text renders as text.",
  },
  {
    id: "flip_content_type",
    scenario: "message",
    env: { EVIL_MODE: "flip_content_type" },
    relay: "Flips the v1 envelope's own contentType, which is inside the AES-GCM AAD.",
    expected: "AES-GCM fails: AUTH_FAILED, message dropped (the AAD no longer matches).",
  },
  {
    id: "swap_key",
    scenario: "handshake",
    env: { EVIL_MODE: "swap_key", EVIL_SWAP_WITH: "__MALLORY__" },
    relay: "Serves Mallory's identity + prekeys when Bob's are requested.",
    expected:
      "KT off: handshake to the wrong key produces undeliverable/unauthenticated messages (no plaintext leaks); KT on: ALERT, key refused.",
  },
  {
    id: "kt_swap_key",
    scenario: "kt",
    kt: true,
    env: { EVIL_MODE: "swap_key", EVIL_SWAP_WITH: "__MALLORY__" },
    relay: "As swap_key, but with key transparency enabled.",
    expected: "KT verifyPeer fails (key not in the log under Bob's name): ALERT, session refused.",
  },
  {
    id: "kt_rogue_leaf",
    scenario: "kt",
    kt: true,
    env: { EVIL_MODE: "kt_rogue_leaf", EVIL_SWAP_WITH: "__MALLORY__", EVIL_KT_VICTIM: "__BOB__" },
    relay:
      "POST /kt/evil/rogue-leaf appends a forged leaf binding Bob's name to Mallory's key; KT register checks are off.",
    expected: "Bob's self-monitoring finds a leaf under his name he did not publish: global KT ALERT.",
  },
  {
    id: "kt_fork",
    scenario: "kt",
    kt: true,
    env: { EVIL_MODE: "kt_fork", EVIL_SWAP_WITH: "__MALLORY__", EVIL_KT_VICTIM: "__BOB__", EVIL_FORK_UA: "KryptForkTarget" },
    relay: "Shows the forked client an extra rogue leaf nobody else sees (split view of the log).",
    expected: "Gossip / consistency check exposes the divergent head: KT ALERT.",
  },
  {
    id: "kt_rewrite",
    scenario: "kt",
    kt: true,
    env: { EVIL_MODE: "kt_rewrite", EVIL_SWAP_WITH: "__MALLORY__", EVIL_KT_REWRITE_INDEX: "0" },
    relay: "Rewrites leaf 0 and re-signs every head, so history differs from what clients already saw.",
    expected: "Consistency with an earlier stored head fails: KT ALERT.",
  },
  {
    id: "impersonation",
    scenario: "impersonation",
    env: {},
    relay:
      "A socket that is not Bob tries to register as Bob (v0: register_socket \"bob\") and drain his mailbox / receive his messages.",
    expected: "v1: the socket has no valid token, so connect is refused (connect_error); identity comes from the token, not a claim.",
  },
  {
    id: "bola",
    scenario: "bola",
    env: {},
    relay:
      "An unauthenticated REST call accepts a friend request on another user's behalf (POST /api/request/accept with someone else's receiver).",
    expected: "v1: 401 without a token, 403 when the token user is not the named acting user.",
  },
];

export const KT_ATTACK_IDS = ATTACKS.filter((a) => a.kt).map((a) => a.id);
