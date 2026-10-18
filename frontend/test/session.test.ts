/**
 * SessionManager tests: the "Tests P must write" table of the implementation
 * plan, run for every ratchet suite.
 */
import { describe, expect, it } from "vitest";
import type { EnvelopeV1 } from "../src/crypto/envelope";
import { HandshakeError } from "../src/crypto/errors";
import { sha256 } from "../src/crypto/kdf";
import { KEM_SUITES } from "../src/crypto/pq";
import { MAX_SKIP, SKIPPED_TTL_MS, createMutexLock } from "../src/crypto/session";
import type { SessionState, SessionStore, PeerRecord } from "../src/crypto/session-store";
import {
  copy,
  expectRejected,
  flipB64,
  managerFor,
  recv,
  rng,
  send,
  shuffle,
  te,
  world,
  type Party,
} from "./helpers";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const state = async (p: Party, peer: string): Promise<SessionState> => (await p.store.load(peer))!.session!;

for (const suite of KEM_SUITES) {
  describe(`[${suite}] round trip`, () => {
    it("1,000 alternating messages", async () => {
      const { alice, bob } = await world({ suite });
      for (let i = 0; i < 500; i++) {
        expect(await recv(bob, await send(alice, bob, `a${i}`))).toBe(`a${i}`);
        expect(await recv(alice, await send(bob, alice, `b${i}`))).toBe(`b${i}`);
      }
      // Every reply is a ratchet step: 1,000 messages -> epoch 999.
      expect((await alice.sm.getStatus("bob"))!.epoch).toBe(999);
      expect((await bob.sm.getStatus("alice"))!.sessionId).toBe((await alice.sm.getStatus("bob"))!.sessionId);
    });

    it("1,000 messages in one direction", async () => {
      const { alice, bob } = await world({ suite });
      for (let i = 0; i < 1000; i++) expect(await recv(bob, await send(alice, bob, `m${i}`))).toBe(`m${i}`);
      const s = await state(bob, "alice");
      expect(s.recvEpoch).toBe(0);
      expect(s.nr).toBe(1000);
      expect(s.skipped).toHaveLength(0);
    });

    it("carries contentType inside the authenticated header", async () => {
      const { alice, bob } = await world({ suite });
      const env = await alice.sm.encrypt("bob", new Uint8Array([1, 2, 3]), "image");
      const r = await bob.sm.decrypt(env);
      expect(r).toMatchObject({ peer: "alice", contentType: "image", epoch: 0, n: 0 });
      expect([...r.plaintext]).toEqual([1, 2, 3]);
    });
  });

  describe(`[${suite}] ordering`, () => {
    it("decrypts any order within the window, across an epoch boundary", async () => {
      const { alice, bob } = await world({ suite });
      const first = await send(alice, bob, "a0");
      const epoch0 = [first];
      for (let i = 1; i < 6; i++) epoch0.push(await send(alice, bob, `a${i}`));
      await recv(bob, first);
      await recv(alice, await send(bob, alice, "b0"));
      const epoch2 = [];
      for (let i = 0; i < 6; i++) epoch2.push(await send(alice, bob, `c${i}`));
      // Epoch-2 messages first (shuffled), then the late epoch-0 ones (shuffled).
      const r = rng(7);
      for (const env of shuffle(epoch2, r)) expect((await recv(bob, env)).startsWith("c")).toBe(true);
      for (const env of shuffle(epoch0.slice(1), r)) expect((await recv(bob, env)).startsWith("a")).toBe(true);
      expect((await state(bob, "alice")).skipped).toHaveLength(0);
    });

    it(`accepts a gap of exactly MAX_SKIP and rejects MAX_SKIP + 1`, async () => {
      const { alice, bob } = await world({ suite });
      const envs: EnvelopeV1[] = [];
      for (let i = 0; i < MAX_SKIP + 3; i++) envs.push(await send(alice, bob, `m${i}`));
      await recv(bob, envs[0]); // nr = 1
      await expectRejected(bob, envs[MAX_SKIP + 2], "TOO_MANY_SKIPPED"); // gap 1001
      expect(await recv(bob, envs[MAX_SKIP + 1])).toBe(`m${MAX_SKIP + 1}`); // gap 1000
      expect((await state(bob, "alice")).skipped).toHaveLength(MAX_SKIP);
    });

    it("rejects a first message whose n is beyond MAX_SKIP", async () => {
      const { alice, bob } = await world({ suite });
      const envs: EnvelopeV1[] = [];
      for (let i = 0; i < MAX_SKIP + 2; i++) envs.push(await send(alice, bob, "x"));
      await expectRejected(bob, envs[MAX_SKIP + 1], "TOO_MANY_SKIPPED");
      await recv(bob, envs[MAX_SKIP]);
    });

    it("rejects duplicates, including a replay of a message decrypted from a skipped key", async () => {
      const { alice, bob } = await world({ suite });
      const e0 = await send(alice, bob, "0");
      const e1 = await send(alice, bob, "1");
      const e2 = await send(alice, bob, "2");
      await recv(bob, e0);
      await recv(bob, e2);
      await expectRejected(bob, e0, "DUPLICATE");
      await expectRejected(bob, e2, "DUPLICATE");
      await recv(bob, e1); // from the skipped cache
      await expectRejected(bob, e1, "DUPLICATE");
    });

    it("rejects an old-epoch message whose key was never cached", async () => {
      const { alice, bob } = await world({ suite });
      const a0 = await send(alice, bob, "a0");
      await recv(bob, a0);
      const b0 = await send(bob, alice, "b0");
      await recv(alice, b0);
      await recv(bob, await send(alice, bob, "a-epoch2"));
      // Bob replays Alice's epoch-0 message after moving on: replay.
      await expectRejected(bob, a0, ["DUPLICATE", "STALE_EPOCH"]);
      await recv(alice, await send(bob, alice, "b-epoch3"));
      await expectRejected(alice, b0, "STALE_EPOCH", "bob");
    });

    it("simultaneous sends from both sides always converge", async () => {
      const { alice, bob } = await world({ suite });
      await recv(bob, await send(alice, bob, "hello"));
      const r = rng(42);
      for (let round = 0; round < 30; round++) {
        const fromA = [];
        const fromB = [];
        const k = 1 + Math.floor(r() * 3);
        // Both sides send before seeing the other's messages: crossing traffic.
        for (let i = 0; i < k; i++) {
          fromA.push(await send(alice, bob, `A${round}.${i}`));
          fromB.push(await send(bob, alice, `B${round}.${i}`));
        }
        for (const env of shuffle(fromA, r)) expect((await recv(bob, env)).startsWith("A")).toBe(true);
        for (const env of shuffle(fromB, r)) expect((await recv(alice, env)).startsWith("B")).toBe(true);
      }
      expect((await alice.sm.getStatus("bob"))!.epoch).toBeGreaterThan(20);
    });
  });

  describe(`[${suite}] tamper: rejected with state unchanged`, () => {
    async function liveSession() {
      const w = await world({ suite });
      await recv(w.bob, await send(w.alice, w.bob, "a0"));
      await recv(w.alice, await send(w.bob, w.alice, "b0"));
      // A ratcheting message (epoch 2) carries kem {ct, ek}.
      const env = await send(w.alice, w.bob, "secret");
      expect(env.kem).toBeDefined();
      return { ...w, env };
    }

    it("bit flips in header fields, ciphertext, tag, KEM ct and ek", async () => {
      const { bob, env } = await liveSession();
      const bodyLen = Buffer.from(env.body, "base64url").length;
      const variants: [string, EnvelopeV1][] = [
        ["body[0]", { ...copy(env), body: flipB64(env.body, 0, 0) }],
        ["tag (last byte)", { ...copy(env), body: flipB64(env.body, bodyLen - 1, 7) }],
        ["kem.ct", { ...copy(env), kem: { ...env.kem!, ct: flipB64(env.kem!.ct, 100, 3) } }],
        ["kem.ek", { ...copy(env), kem: { ...env.kem!, ek: flipB64(env.kem!.ek, 5, 1) } }],
        ["contentType", { ...copy(env), contentType: "image" }],
        ["n", { ...copy(env), n: env.n + 1 }],
        ["pn", { ...copy(env), pn: env.pn + 1 }],
      ];
      for (const [, v] of variants) await expectRejected(bob, v, ["AUTH_FAILED", "BAD_HEADER"]);
      // The untampered message still decrypts afterwards.
      expect(await recv(bob, env)).toBe("secret");
    });

    it("wrong session id, wrong epoch, wrong recipient, dropped ratchet data", async () => {
      const { bob, env } = await liveSession();
      await expectRejected(bob, { ...copy(env), sessionId: flipB64(env.sessionId) }, "UNKNOWN_SESSION");
      await expectRejected(bob, { ...copy(env), epoch: env.epoch + 2 }, "BAD_EPOCH");
      await expectRejected(bob, { ...copy(env), epoch: env.epoch + 1 }, "BAD_EPOCH"); // our own parity
      await expectRejected(bob, { ...copy(env), epoch: 0 }, ["AUTH_FAILED", "MALFORMED"]);
      const noKem = copy(env);
      delete noKem.kem;
      await expectRejected(bob, noKem, "BAD_EPOCH");
      await expectRejected(bob, { ...copy(env), to: "carol" }, "NOT_FOR_ME");
      await expectRejected(bob, { ...copy(env), suite: "mlkem768" }, "MALFORMED");
      expect(await recv(bob, env)).toBe("secret");
    });

    it("a message moved into another session fails", async () => {
      const w1 = await liveSession();
      const w2 = await liveSession();
      // Same usernames, different sessions: w1's message cannot be read in w2.
      await expectRejected(w2.bob, w1.env, "UNKNOWN_SESSION");
    });

    it("bit flips in the init header", async () => {
      const { alice, bob } = await world({ suite });
      const env = await send(alice, bob, "first");
      const i = env.init!;
      const variants: EnvelopeV1[] = [
        { ...copy(env), init: { ...i, ct1: flipB64(i.ct1, 10) } },
        { ...copy(env), init: { ...i, ct2: flipB64(i.ct2!, 10) } },
        { ...copy(env), init: { ...i, ek: flipB64(i.ek, 10) } },
        { ...copy(env), init: { ...i, sig: flipB64(i.sig, 10) } },
        { ...copy(env), init: { ...i, spkId: i.spkId ^ 1 } },
        { ...copy(env), body: flipB64(env.body, 3) },
      ];
      for (const v of variants) {
        await expectRejected(bob, v, ["BAD_SIGNATURE", "UNKNOWN_PREKEY", "AUTH_FAILED"]);
      }
      expect(bob.store.raw("alice")).toBeUndefined();
      expect(await recv(bob, env)).toBe("first");
    });
  });

  describe(`[${suite}] handshake`, () => {
    it("rejects an init replay for a closed session", async () => {
      const { alice, bob } = await world({ suite });
      const first = await send(alice, bob, "hi");
      await recv(bob, first);
      await bob.sm.closeSession("alice");
      await expectRejected(bob, first, "SESSION_CLOSED");
    });

    it("rejects an init replay for an old session even after its tombstone is gone (session-id memory)", async () => {
      for (const withOpk of [true, false]) {
        const { dir, alice, bob } = await world({ suite, oneTimeCount: withOpk ? 3 : 0 });
        const first = await send(alice, bob, "hi");
        expect(first.init!.opkId === null).toBe(!withOpk);
        await recv(bob, first);
        // Bob loses his session store (or the 32-entry tombstone list rolled over).
        bob.store = new (bob.store.constructor as new () => typeof bob.store)();
        bob.sm = managerFor(bob, dir, { suite });
        await expectRejected(bob, first, "INIT_REPLAY");
      }
    });

    it("a repeated init header on a live session is the same session (no reset)", async () => {
      const { alice, bob } = await world({ suite });
      const e0 = await send(alice, bob, "0");
      const e1 = await send(alice, bob, "1");
      const e2 = await send(alice, bob, "2");
      expect(e1.init).toEqual(e0.init);
      expect(e2.init).toEqual(e0.init);
      await recv(bob, e0);
      const sid = (await bob.sm.getStatus("alice"))!.sessionId;
      await recv(bob, e2);
      // Bob replies (epoch 1); a delayed epoch-0 message with the init header still decrypts.
      await recv(alice, await send(bob, alice, "b0"));
      expect(await recv(bob, e1)).toBe("1");
      expect((await bob.sm.getStatus("alice"))!.sessionId).toBe(sid);
      expect((await state(bob, "alice")).nr).toBe(3);
      // After Bob's reply arrived, Alice stops sending the init header.
      const later = await send(alice, bob, "later");
      expect(later.init).toBeUndefined();
      expect(later.epoch).toBe(2);
    });

    it("rejects a bundle with a swapped prekey signature", async () => {
      const { dir, alice } = await world({ suite });
      dir.tamper = (b) => ({ ...b, signedPrekey: { ...b.signedPrekey!, signature: b.oneTimePrekey!.signature } });
      await expect(alice.sm.encrypt("bob", te.encode("x"), "text")).rejects.toThrow(HandshakeError);
      dir.tamper = (b) => ({ ...b, signedPrekey: b.oneTimePrekey }); // OPK passed off as SPK
      await expect(alice.sm.encrypt("bob", te.encode("x"), "text")).rejects.toMatchObject({ code: "BAD_PREKEY_SIGNATURE" });
      expect(alice.store.raw("bob")).toBeUndefined();
    });

    it("falls back to the signed prekey when the one-time pool is empty", async () => {
      const { alice, bob } = await world({ suite, oneTimeCount: 0 });
      const env = await send(alice, bob, "spk only");
      expect(env.init!.opkId).toBeNull();
      expect(env.init!.ct2).toBeNull();
      expect(await recv(bob, env)).toBe("spk only");
      expect(await recv(alice, await send(bob, alice, "reply"))).toBe("reply");
    });

    it("deletes the one-time prekey after use and remembers the session id", async () => {
      const { alice, bob } = await world({ suite });
      const env = await send(alice, bob, "x");
      expect(await bob.prekeys.getOneTimePrekey(env.init!.opkId!)).toBeDefined();
      await recv(bob, env);
      expect(await bob.prekeys.getOneTimePrekey(env.init!.opkId!)).toBeUndefined();
      expect(await bob.prekeys.hasAcceptedSession(env.init!.spkId, env.sessionId)).toBe(true);
    });

    it("concurrent deliveries of one init are serialized: exactly one is accepted", async () => {
      for (const withOpk of [true, false]) {
        const { dir, alice, bob } = await world({ suite, oneTimeCount: withOpk ? 3 : 0 });
        const env = await send(alice, bob, "once");
        // Two tabs of Bob, sharing his stores and one lock (navigator.locks in a browser).
        const lock = createMutexLock();
        const tabs = [managerFor(bob, dir, { suite, lock }), managerFor(bob, dir, { suite, lock })];
        const results = await Promise.allSettled([...tabs, ...tabs].map((t) => t.decrypt(copy(env))));
        const ok = results.filter((r) => r.status === "fulfilled");
        const codes = results.flatMap((r) => (r.status === "rejected" ? [(r.reason as { code: string }).code] : []));
        expect(ok).toHaveLength(1);
        // Later copies hit the live session (n already received), never a second handshake.
        expect(codes).toEqual(["DUPLICATE", "DUPLICATE", "DUPLICATE"]);
      }
    });

    it("an init naming the SPK's keyId as an OPK finds nothing (separate keyId namespaces)", async () => {
      const { alice, bob } = await world({ suite });
      const env = await send(alice, bob, "x");
      const forged = { ...copy(env), init: { ...env.init!, opkId: env.init!.spkId } };
      await expectRejected(bob, forged, "UNKNOWN_PREKEY");
      expect(await recv(bob, env)).toBe("x");
    });

    it("an OPK whose keyId equals the SPK's keyId does not shadow it", async () => {
      const { alice, bob } = await world({ suite, oneTimeCount: 0 });
      const spkId = (await bob.prekeys.listSignedPrekeyIds())[0];
      const spk = (await bob.prekeys.getSignedPrekey(spkId))!;
      const { mlkem1024 } = await import("../src/crypto/pq");
      const other = mlkem1024.keygen();
      await bob.prekeys.putOneTimePrekeys([{ keyId: spkId, ...other, createdAt: 0 }]);
      expect((await bob.prekeys.getSignedPrekey(spkId))!.publicKey).toEqual(spk.publicKey);
      expect(await recv(bob, await send(alice, bob, "spk still works"))).toBe("spk still works");
      await bob.prekeys.deleteOneTimePrekey(spkId);
      expect(await bob.prekeys.getSignedPrekey(spkId)).toBeDefined();
    });

    it("rejects a replayed SPK-only handshake via the H(T) memory", async () => {
      const { dir, alice, bob } = await world({ suite, oneTimeCount: 0 });
      const env = await send(alice, bob, "x");
      await recv(bob, env);
      bob.store = new (bob.store.constructor as new () => typeof bob.store)();
      bob.sm = managerFor(bob, dir, { suite });
      await expectRejected(bob, env, "INIT_REPLAY");
    });

    it("lost first message: the session starts from a later epoch-0 message", async () => {
      const { alice, bob } = await world({ suite });
      const lost = await send(alice, bob, "0");
      const e1 = await send(alice, bob, "1");
      expect(await recv(bob, e1)).toBe("1");
      expect(await recv(alice, await send(bob, alice, "ack"))).toBe("ack");
      expect(await recv(bob, lost)).toBe("0"); // arrives late, from the skipped cache
    });

    it("simultaneous initiation converges on the smaller session id", async () => {
      const { alice, bob } = await world({ suite });
      const fromA = await send(alice, bob, "hi from alice");
      const fromB = await send(bob, alice, "hi from bob");
      const winner = Buffer.from(fromA.sessionId, "base64url").compare(Buffer.from(fromB.sessionId, "base64url")) < 0 ? "A" : "B";
      // The losing init authenticates, so its id is tombstoned (spec 4.5) and
      // a second copy is refused without touching anything.
      if (winner === "A") {
        expect(await recv(bob, fromA)).toBe("hi from alice");
        await expect(alice.sm.decrypt(fromB)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
        await expectRejected(alice, fromB, "SESSION_CLOSED", "bob");
      } else {
        expect(await recv(alice, fromB)).toBe("hi from bob");
        await expect(bob.sm.decrypt(fromA)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
        await expectRejected(bob, fromA, "SESSION_CLOSED");
      }
      // Delivery in the other order gives the same outcome; then both talk on one session.
      const sid = winner === "A" ? fromA.sessionId : fromB.sessionId;
      for (let i = 0; i < 3; i++) {
        expect(await recv(bob, await send(alice, bob, `a${i}`))).toBe(`a${i}`);
        expect(await recv(alice, await send(bob, alice, `b${i}`))).toBe(`b${i}`);
      }
      expect((await alice.sm.getStatus("bob"))!.sessionId).toBe(sid);
      expect((await bob.sm.getStatus("alice"))!.sessionId).toBe(sid);
    });

    it("a peer that lost its state can start over; the old session is tombstoned", async () => {
      const { dir, alice, bob } = await world({ suite });
      const old = await send(alice, bob, "old");
      await recv(bob, old);
      await recv(alice, await send(bob, alice, "ack"));
      alice.store = new (alice.store.constructor as new () => typeof alice.store)();
      alice.sm = managerFor(alice, dir, { suite });
      const fresh = await send(alice, bob, "new device");
      expect(await recv(bob, fresh)).toBe("new device");
      expect((await bob.sm.getStatus("alice"))!.sessionId).toBe(fresh.sessionId);
      await expectRejected(bob, old, "SESSION_CLOSED");
    });
  });

  describe(`[${suite}] epochs`, () => {
    it("both sides derive identical root and chain keys for epochs 0-5", async () => {
      const { alice, bob } = await world({ suite });
      let [sender, receiver] = [alice, bob];
      for (let e = 0; e <= 5; e++) {
        const env = await send(sender, receiver, `e${e}`);
        expect(env.epoch).toBe(e);
        await recv(receiver, env);
        const s = await state(sender, receiver.name);
        const r = await state(receiver, sender.name);
        expect(s.sendEpoch).toBe(e);
        expect(r.recvEpoch).toBe(e);
        expect(hex(await sha256(s.cks!))).toBe(hex(await sha256(r.ckr!)));
        if (e > 0) expect(hex(await sha256(s.rk))).toBe(hex(await sha256(r.rk)));
        [sender, receiver] = [receiver, sender];
      }
    });
  });

  describe(`[${suite}] rollback safety`, () => {
    it("concurrent encrypts in one tab never reuse a chain key", async () => {
      const { alice, bob } = await world({ suite });
      await recv(bob, await send(alice, bob, "start"));
      const envs = await Promise.all(Array.from({ length: 40 }, (_, i) => send(alice, bob, `c${i}`)));
      expect(new Set(envs.map((e) => `${e.epoch}/${e.n}`)).size).toBe(40);
      for (const env of envs) await recv(bob, env);
    });

    it("two tabs sharing one store and one lock never reuse a chain key", async () => {
      const { dir, alice, bob } = await world({ suite });
      await recv(bob, await send(alice, bob, "start"));
      const lock = createMutexLock(); // stands in for navigator.locks shared across tabs
      const tab1 = managerFor(alice, dir, { suite, lock });
      const tab2 = managerFor(alice, dir, { suite, lock });
      const envs = await Promise.all(
        Array.from({ length: 30 }, (_, i) => (i % 2 ? tab1 : tab2).encrypt("bob", te.encode(`t${i}`), "text")),
      );
      expect(new Set(envs.map((e) => `${e.epoch}/${e.n}`)).size).toBe(30);
      for (const env of envs) await recv(bob, env);
    });

    it("a failed persist means no envelope; the chain never reuses a key", async () => {
      const { dir, alice, bob } = await world({ suite });
      let failNext = false;
      const flaky: SessionStore = {
        load: (p) => alice.store.load(p),
        save: async (p: string, rec: PeerRecord) => {
          if (failNext) {
            failNext = false;
            throw new Error("disk full");
          }
          return alice.store.save(p, rec);
        },
      };
      const sm = managerFor(alice, dir, { suite, store: flaky });
      const seen = new Set<string>();
      for (let i = 0; i < 10; i++) {
        failNext = i % 3 === 1;
        try {
          const env = await sm.encrypt("bob", te.encode(`m${i}`), "text");
          const id = `${env.epoch}/${env.n}`;
          expect(seen.has(id)).toBe(false);
          seen.add(id);
          expect(await recv(bob, env)).toBe(`m${i}`);
        } catch (e) {
          expect((e as Error).message).toBe("disk full");
        }
      }
      expect(seen.size).toBe(7); // 10 attempts, 3 failed persists
    });
  });

  describe(`[${suite}] post-compromise recovery`, () => {
    it("a passive attacker with Alice's state at message k loses access at Alice's first message after Bob's reply", async () => {
      const { dir, alice, bob } = await world({ suite });
      await recv(bob, await send(alice, bob, "a0"));
      await recv(alice, await send(bob, alice, "b0"));
      await recv(bob, await send(alice, bob, "a1 (epoch 2)"));

      // Compromise: Eve copies Alice's whole device state at message k.
      const stolen = alice.store.clone();
      const eve = managerFor({ ...alice, store: stolen }, dir, { suite });
      const stolenState = (await stolen.load("bob"))!.session!;
      let eveCk = stolenState.cks!;
      let eveN = stolenState.ns;
      const { kdfChain, messageKeyAndIv, aesGcmDecrypt } = await import("../src/crypto/kdf");
      const { parseEnvelope, headerAad } = await import("../src/crypto/envelope");
      /** Eve reads an Alice->Bob message by walking the stolen sending chain. */
      async function eveReadsAlice(env: EnvelopeV1): Promise<string | null> {
        const parsed = parseEnvelope(env);
        if (parsed.header.epoch !== stolenState.sendEpoch) return null;
        while (eveN < parsed.header.n) {
          eveCk = (await kdfChain(eveCk)).ck;
          eveN++;
        }
        const { mk, ck } = await kdfChain(eveCk);
        eveCk = ck;
        eveN++;
        const { key, iv } = await messageKeyAndIv(mk);
        try {
          return new TextDecoder().decode(await aesGcmDecrypt(key, iv, parsed.body, headerAad(parsed.header)));
        } catch {
          return null;
        }
      }

      // 1. The rest of Alice's current epoch is exposed.
      const rest = [await send(alice, bob, "a2"), await send(alice, bob, "a3")];
      for (const env of rest) {
        expect(await eveReadsAlice(env)).not.toBeNull();
        await recv(bob, env);
      }
      // 2. Bob's next reply encapsulates to Alice's stolen key: exposed.
      const bobReply = await send(bob, alice, "b1 (epoch 3)");
      expect(new TextDecoder().decode((await eve.decrypt(bobReply)).plaintext)).toBe("b1 (epoch 3)");
      await recv(alice, bobReply);

      // 3. Alice's first message after Bob's reply uses fresh randomness: Eve is out.
      const healed = await send(alice, bob, "a4 (epoch 4)");
      expect(healed.epoch).toBe(4);
      expect(await eveReadsAlice(healed)).toBeNull();
      await expect(eve.decrypt(healed)).rejects.toThrow(); // not addressed to her chain either
      expect(await recv(bob, healed)).toBe("a4 (epoch 4)");

      // 4. And Bob's next reply is encapsulated to Alice's new key, which Eve lacks.
      const bobNext = await send(bob, alice, "b2 (epoch 5)");
      await expect(eve.decrypt(bobNext)).rejects.toMatchObject({ code: "BAD_EPOCH" });
      expect(await recv(alice, bobNext)).toBe("b2 (epoch 5)");
    });
  });
}

describe("sparse mode (ratchetEveryK)", () => {
  it("K = 10: ratchets only after 10 messages per chain and drops ratchet data once acknowledged", async () => {
    const { alice, bob } = await world({ ratchetEveryK: 10 });
    let kemHeaders = 0;
    let total = 0;
    for (let round = 0; round < 40; round++) {
      for (let i = 0; i < 2; i++) {
        const a = await send(alice, bob, `a${round}.${i}`);
        if (a.kem || a.init) kemHeaders++;
        total++;
        expect(await recv(bob, a)).toBe(`a${round}.${i}`);
        const b = await send(bob, alice, `b${round}.${i}`);
        if (b.kem || b.init) kemHeaders++;
        total++;
        expect(await recv(alice, b)).toBe(`b${round}.${i}`);
      }
    }
    const status = (await alice.sm.getStatus("bob"))!;
    // 160 messages; each side ratchets once per 10 sends -> about 16 epochs, not 160.
    expect(status.epoch).toBeGreaterThan(8);
    expect(status.epoch).toBeLessThan(20);
    // With strictly alternating traffic a chain's ratchet data is acknowledged
    // only when the peer ratchets (after its own K sends), so roughly half the
    // headers still carry it; the saving is in the number of KEM operations.
    expect(kemHeaders).toBeLessThan(total);
    expect(total - kemHeaders).toBeGreaterThan(total / 4);
  });

  it("K = 1 attaches ratchet data to every message", async () => {
    const { alice, bob } = await world({ ratchetEveryK: 1 });
    for (let i = 0; i < 10; i++) {
      const a = await send(alice, bob, "a");
      expect(Boolean(a.kem || a.init)).toBe(true);
      await recv(bob, a);
      const b = await send(bob, alice, "b");
      expect(b.kem).toBeDefined();
      await recv(alice, b);
    }
  });
});

describe("skipped-key lifetime", () => {
  it("skipped keys expire after 7 days", async () => {
    let now = 1_000_000;
    const { alice, bob } = await world({ now: () => now });
    const e0 = await send(alice, bob, "0");
    const e1 = await send(alice, bob, "1");
    const e2 = await send(alice, bob, "2");
    await recv(bob, e0);
    await recv(bob, e2); // caches the key for n = 1
    expect((await state(bob, "alice")).skipped).toHaveLength(1);
    now += SKIPPED_TTL_MS + 1;
    await expectRejected(bob, e1, "DUPLICATE");
    await recv(bob, await send(alice, bob, "3"));
    expect((await state(bob, "alice")).skipped).toHaveLength(0);
  });

  it("only the current and previous receiving epochs keep skipped keys", async () => {
    const { alice, bob } = await world();
    await recv(bob, await send(alice, bob, "a0"));
    const lostA = await send(alice, bob, "a1 lost");
    const a2 = await send(alice, bob, "a2");
    await recv(bob, a2); // caches epoch-0 n=1
    for (let i = 0; i < 2; i++) {
      await recv(alice, await send(bob, alice, "b"));
      await recv(bob, await send(alice, bob, "a"));
    }
    // Bob is now receiving epoch 4; epoch 0 is two receive epochs back.
    expect((await state(bob, "alice")).recvEpoch).toBe(4);
    await expectRejected(bob, lostA, "STALE_EPOCH");
  });
});

describe("saved sessions from removed suites", () => {
  // Before v1 shipped, ratchets could run ML-KEM-768 or X-Wing. A record saved
  // then must not crash ratchetKem(): it is closed on load and the next send
  // runs a fresh ML-KEM-1024 handshake.
  const ageSuite = async (p: Party, peer: string, suite: string) => {
    const rec = (await p.store.load(peer))!;
    await p.store.save(peer, { ...rec, session: { ...rec.session!, suite: suite as SessionState["suite"] } });
  };

  for (const old of ["mlkem768", "xwing"]) {
    it(`a saved ${old} session is closed and replaced by an ML-KEM-1024 handshake`, async () => {
      const { alice, bob } = await world();
      await recv(bob, await send(alice, bob, "before"));
      await recv(alice, await send(bob, alice, "reply"));
      const oldSid = (await alice.sm.getStatus("bob"))!.sessionId;
      const stale = await send(alice, bob, "in flight");
      await ageSuite(alice, "bob", old);
      await ageSuite(bob, "alice", old);

      const env = await send(alice, bob, "after");
      expect(env.init).toBeDefined();
      expect(env.suite).toBe("mlkem1024");
      expect(env.sessionId).not.toBe(oldSid);
      expect(await recv(bob, env)).toBe("after");
      expect(await recv(alice, await send(bob, alice, "ok"))).toBe("ok");

      // The old session id is tombstoned, so its messages are refused.
      expect((await alice.store.load("bob"))!.closed).toContain(oldSid);
      await expectRejected(bob, stale, "SESSION_CLOSED");
    });
  }
});
