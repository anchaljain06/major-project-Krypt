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
import { MemorySessionStore } from "../src/crypto/session-store";
import { copy, expectRejected, flipB64, managerFor, recv, send, te, world } from "./helpers";

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

  /** Simultaneous initiation; returns the parties ordered by the bytewise tie-break. */
  async function race() {
    const w = await world();
    const { alice, bob } = w;
    const fromAlice = await send(alice, bob, "a0");
    const fromBob = await send(bob, alice, "b0");
    // Raw bytes, not base64url strings: the alphabet's value order (A-Z, a-z,
    // 0-9, -, _) is not ASCII order, so string comparison can pick the other id.
    const aliceWins = compareBytes(fromBase64url(fromAlice.sessionId), fromBase64url(fromBob.sessionId)) < 0;
    const [winner, loser, winnerEnv, loserEnv] = aliceWins
      ? [alice, bob, fromAlice, fromBob]
      : [bob, alice, fromBob, fromAlice];
    return { ...w, winner, loser, winnerEnv, loserEnv };
  }
  type Race = Awaited<ReturnType<typeof race>>;

  /** Loser accepts the winner's init and re-sends; the winner's session is then confirmed. */
  async function settle(r: Race) {
    await r.loser.sm.decrypt(r.winnerEnv);
    expect(await recv(r.winner, await r.loser.sm.encrypt(r.winner.name, te.encode("resent"), "text"))).toBe("resent");
    expect((await r.winner.sm.getStatus(r.loser.name))!.established).toBe(true);
  }

  async function bothTalk(r: Race) {
    for (let i = 0; i < 2; i++) {
      expect(await recv(r.loser, await send(r.winner, r.loser, `w${i}`))).toBe(`w${i}`);
      expect(await recv(r.winner, await send(r.loser, r.winner, `l${i}`))).toBe(`l${i}`);
    }
    expect((await r.winner.sm.getStatus(r.loser.name))!.sessionId).toBe(r.winnerEnv.sessionId);
    expect((await r.loser.sm.getStatus(r.winner.name))!.sessionId).toBe(r.winnerEnv.sessionId);
  }

  // Found during integration: an init rejected with SESSION_SUPERSEDED used to
  // leave no trace, so a later copy matched the "peer started over" row of
  // spec 4.5 once the winning session was confirmed, replaced it, and both
  // sides then got SESSION_CLOSED. An authenticated loser is now tombstoned.
  it("a superseded init delivered again after confirmation is rejected", async () => {
    const r = await race();
    await expect(r.winner.sm.decrypt(r.loserEnv)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
    await settle(r);
    await expectRejected(r.winner, r.loserEnv, "SESSION_CLOSED", r.loser.name);
  });

  it("a relay replay of the losing init after confirmation leaves the agreed session intact", async () => {
    const r = await race();
    await expect(r.winner.sm.decrypt(r.loserEnv)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
    await settle(r);
    for (let i = 0; i < 3; i++) {
      await expect(r.winner.sm.decrypt(copy(r.loserEnv))).rejects.toBeInstanceOf(DecryptError);
    }
    await bothTalk(r);
  });

  it("duplicate delivery of the losing init: both copies are refused, the first is recorded", async () => {
    const r = await race();
    await expect(r.winner.sm.decrypt(r.loserEnv)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
    // The live session is untouched; only the tombstone list grew.
    const rec = (await r.winner.store.load(r.loser.name))!;
    expect(toBase64url(rec.session!.sessionId)).toBe(r.winnerEnv.sessionId);
    expect(rec.session!.established).toBe(false);
    expect(rec.closed).toEqual([r.loserEnv.sessionId]);
    // The losing init's OPK is used up and its id is in the session-id memory.
    expect(await r.winner.prekeys.getOneTimePrekey(r.loserEnv.init!.opkId!)).toBeUndefined();
    expect(await r.winner.prekeys.hasAcceptedSession(r.loserEnv.init!.spkId, r.loserEnv.sessionId)).toBe(true);
    // Further copies, before or after confirmation, change nothing.
    await expectRejected(r.winner, copy(r.loserEnv), "SESSION_CLOSED", r.loser.name);
    await settle(r);
    await expectRejected(r.winner, copy(r.loserEnv), "SESSION_CLOSED", r.loser.name);
    await bothTalk(r);
  });

  it("a forged losing init that does not authenticate records nothing", async () => {
    const r = await race();
    const forged = { ...r.loserEnv, body: flipB64(r.loserEnv.body, 20) };
    await expectRejected(r.winner, forged, "SESSION_SUPERSEDED", r.loser.name);
    // The genuine copy is still recognised and tombstoned afterwards.
    await expect(r.winner.sm.decrypt(r.loserEnv)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
    await settle(r);
    await expectRejected(r.winner, r.loserEnv, "SESSION_CLOSED", r.loser.name);
  });

  it("a genuine restart after a wipe (new transcript, new sessionId) is still accepted", async () => {
    const r = await race();
    await expect(r.winner.sm.decrypt(r.loserEnv)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
    await settle(r);
    const stale = await send(r.loser, r.winner, "sent on the agreed session, delivered late");
    // The loser loses its session store (cleared site data) and starts over.
    r.loser.store = new MemorySessionStore();
    r.loser.sm = managerFor(r.loser, r.dir);
    const restart = await send(r.loser, r.winner, "new device");
    expect(restart.sessionId).not.toBe(r.loserEnv.sessionId);
    expect(restart.sessionId).not.toBe(r.winnerEnv.sessionId);
    expect(await recv(r.winner, restart)).toBe("new device");
    expect((await r.winner.sm.getStatus(r.loser.name))!.sessionId).toBe(restart.sessionId);
    expect(await recv(r.loser, await send(r.winner, r.loser, "welcome back"))).toBe("welcome back");
    // The old losing init and the replaced session stay dead.
    await expectRejected(r.winner, r.loserEnv, "SESSION_CLOSED", r.loser.name);
    await expectRejected(r.winner, stale, "SESSION_CLOSED", r.loser.name);
  });
});
