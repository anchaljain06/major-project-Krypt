import { describe, expect, it } from "vitest";
import {
  buildWirePayload,
  classifyIncoming,
  encodeAppMessage,
  frameSize,
  parseAppMessage,
  type AppMessage,
} from "../src/crypto/appMessage";
import { compareBytes, fromBase64url, toBase64url } from "../src/crypto/encoding";
import {
  AttachmentError,
  MAX_ATTACHMENT_BYTES,
  MAX_SOCKET_MESSAGE_BYTES,
  assertAttachmentFits,
  decryptAttachment,
  encryptAttachment,
} from "../src/crypto/media";
import { mldsaKeygen } from "../src/crypto/pq";
import { safetyNumber } from "../src/crypto/safetyNumber";
import { DecryptError } from "../src/crypto/errors";
import { recv, send, te, world } from "./helpers";

describe("attachments", () => {
  it("round-trips and binds key, hash and mime", async () => {
    const data = crypto.getRandomValues(new Uint8Array(5000));
    const { meta, ciphertext } = await encryptAttachment(data, "image/jpeg");
    expect(await decryptAttachment(ciphertext, meta)).toEqual(data);

    const flipped = ciphertext.slice();
    flipped[10] ^= 1;
    await expect(decryptAttachment(flipped, meta)).rejects.toThrow(AttachmentError);
    // Fix up the hash so only GCM catches it.
    const { sha256 } = await import("../src/crypto/kdf");
    await expect(decryptAttachment(flipped, { ...meta, sha256: toBase64url(await sha256(flipped)) })).rejects.toThrow(
      /authentication/,
    );
    await expect(decryptAttachment(ciphertext, { ...meta, mime: "image/png" })).rejects.toThrow(/authentication/);
    await expect(decryptAttachment(ciphertext, { ...meta, size: meta.size + 1 })).rejects.toThrow(/size/);
  });

  it("caps attachments so the whole frame fits the relay's 16 MiB limit", () => {
    expect(MAX_ATTACHMENT_BYTES).toBe(12_533_744);
    expect(() => assertAttachmentFits(MAX_ATTACHMENT_BYTES)).not.toThrow();
    expect(() => assertAttachmentFits(MAX_ATTACHMENT_BYTES + 1)).toThrow(/too large/);
    // A maximal attachment, base64url-encoded, plus a worst-case envelope still fits.
    const attachmentChars = Math.ceil(((MAX_ATTACHMENT_BYTES + 16) * 4) / 3);
    const worstEnvelope = 20_000;
    expect(attachmentChars + worstEnvelope).toBeLessThan(MAX_SOCKET_MESSAGE_BYTES);
  });
});

describe("app messages and frames", () => {
  const base: AppMessage = { v: 1, id: "abc", sentAt: 1 };

  it("checks the plaintext against the authenticated contentType", async () => {
    const m = parseAppMessage(encodeAppMessage({ ...base, text: "hi", kt: { treeSize: 3, rootHash: "x" } }), "text");
    expect(m.text).toBe("hi");
    expect(m.kt).toEqual({ treeSize: 3, rootHash: "x" });
    expect(() => parseAppMessage(encodeAppMessage(base), "text")).toThrow();
    expect(() => parseAppMessage(encodeAppMessage({ ...base, text: "hi" }), "video")).toThrow(/unsupported/);
    const { meta } = await encryptAttachment(new Uint8Array(10), "audio/mpeg");
    expect(parseAppMessage(encodeAppMessage({ ...base, file: meta }), "audio").file).toEqual(meta);
    // An audio file claimed as an image is refused.
    expect(() => parseAppMessage(encodeAppMessage({ ...base, file: meta }), "image")).toThrow(/carries/);
  });

  it("classifies relayed frames without trusting them", async () => {
    const { alice, bob } = await world();
    const env = await send(alice, bob, "hello");
    const frame = { ...buildWirePayload(env), from: "alice" };
    expect(classifyIncoming(frame).kind).toBe("v1");
    expect(frameSize(buildWirePayload(env))).toBeLessThan(64 * 1024);
    // Relay-stamped sender must match the envelope.
    expect(classifyIncoming({ ...frame, from: "mallory" }).kind).toBe("malformed");
    expect(classifyIncoming({ to: "bob", from: "alice", ciphertext: "GCM:abc", type: "text" }).kind).toBe("v0");
    expect(classifyIncoming(null).kind).toBe("malformed");
    // The evil relay's flip_type changes only the outer `type`; the envelope is what counts.
    expect(classifyIncoming({ ...frame, type: "image" }).kind).toBe("v1");
  });
});

describe("safety numbers", () => {
  it("are 12 groups of 5 digits, identical on both sides", async () => {
    const a = mldsaKeygen().publicKey;
    const b = mldsaKeygen().publicKey;
    const ab = await safetyNumber(a, b);
    expect(ab).toHaveLength(12);
    ab.forEach((g) => expect(g).toMatch(/^\d{5}$/));
    expect(await safetyNumber(b, a)).toEqual(ab);
    expect(await safetyNumber(a, mldsaKeygen().publicKey)).not.toEqual(ab);
  });
});

describe("session race recovery (what services/messaging.ts relies on)", () => {
  it("the losing initiator sees its session replaced on the next authenticated message", async () => {
    const { alice, bob } = await world();
    const fromAlice = await send(alice, bob, "a0");
    const fromBob = await send(bob, alice, "b0");
    // Spec 4.5: the bytewise smaller session id wins (not the base64url string order).
    const aliceFirst = compareBytes(fromBase64url(fromAlice.sessionId), fromBase64url(fromBob.sessionId)) < 0;
    const [winner, loser, winnerEnv, loserEnv] = aliceFirst
      ? [alice, bob, fromAlice, fromBob]
      : [bob, alice, fromBob, fromAlice];

    // The winner rejects the loser's init and keeps its own session.
    await expect(winner.sm.decrypt(loserEnv)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
    // The loser accepts the winner's init; the result names a different session.
    const r = await loser.sm.decrypt(winnerEnv);
    expect(r.sessionId).toBe(winnerEnv.sessionId);
    expect(r.sessionId).not.toBe(loserEnv.sessionId);
    // Re-sending the lost plaintext now works on the surviving session.
    const again = await loser.sm.encrypt(winner.name, te.encode("resent"), "text");
    expect(again.sessionId).toBe(winnerEnv.sessionId);
    expect(await recv(winner, again)).toBe("resent");
  });

  // KNOWN PROTOCOL ISSUE (found during integration). An init rejected with
  // SESSION_SUPERSEDED leaves no trace (no state change on error), so once the
  // winning session is confirmed, a late or replayed copy of that same init
  // matches the "peer started over" row of spec 4.5 and replaces the agreed
  // session. The loser has tombstoned that id, so both sides end up with
  // SESSION_CLOSED. `it.fails` flips to a failure once this is fixed.
  it.fails("a superseded init delivered again after confirmation is rejected", async () => {
    const { alice, bob } = await world();
    const fromAlice = await send(alice, bob, "a0");
    const fromBob = await send(bob, alice, "b0");
    const aliceWins = compareBytes(fromBase64url(fromAlice.sessionId), fromBase64url(fromBob.sessionId)) < 0;
    const [winner, loser, winnerEnv, loserEnv] = aliceWins
      ? [alice, bob, fromAlice, fromBob]
      : [bob, alice, fromBob, fromAlice];
    await expect(winner.sm.decrypt(loserEnv)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
    await loser.sm.decrypt(winnerEnv);
    await recv(winner, await loser.sm.encrypt(winner.name, te.encode("resent"), "text"));
    // Replay of the superseded init: should be refused, is accepted today.
    await expect(winner.sm.decrypt(loserEnv)).rejects.toBeInstanceOf(DecryptError);
  });
});
