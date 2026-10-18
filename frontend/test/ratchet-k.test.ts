/**
 * Ratchet tests at every supported K (ratchetEveryK), as listed in the
 * file-transfer/KEM plan section 9.4. K changes when a send step happens,
 * never the wire format, so every case must hold for K = 1, 4, 8 and 16.
 */
import { describe, expect, it } from "vitest";
import { sha256 } from "@krypt/shared";
import type { EnvelopeV1 } from "../src/crypto/envelope";
import type { SessionState } from "../src/crypto/session-store";
import { copy, expectRejected, flipB64, managerFor, recv, rng, send, shuffle, world, type Party } from "./helpers";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const state = async (p: Party, peer: string): Promise<SessionState> => (await p.store.load(peer))!.session!;
const resizeB64 = (s: string, len: number) => Buffer.from(s, "base64url").subarray(0, len).toString("base64url");

/** Alice sends a0, Bob replies b0: Alice now holds Bob's ratchet key and has sent 1 message on epoch 0. */
async function started(K: number) {
  const w = await world({ ratchetEveryK: K });
  await recv(w.bob, await send(w.alice, w.bob, "a0"));
  await recv(w.alice, await send(w.bob, w.alice, "b0"));
  return w;
}

/** Sends until the sender's next send step, returning every envelope sent (the last one opens the new epoch). */
async function untilStep(from: Party, to: Party): Promise<EnvelopeV1[]> {
  const out: EnvelopeV1[] = [];
  const start = (await state(from, to.name)).sendEpoch;
  for (let i = 0; i < 64; i++) {
    const env = await send(from, to, `s${i}`);
    out.push(env);
    if (env.epoch !== start) return out;
  }
  throw new Error("no send step within 64 messages");
}

describe.each([1, 4, 8, 16])("K = %i", (K) => {
  it("both sides derive the same root and chain keys through six epochs", async () => {
    const { alice, bob } = await world({ ratchetEveryK: K });
    let [sender, receiver] = [alice, bob];
    let epochsSeen = 0;
    for (let round = 0; round < 12 && epochsSeen < 6; round++) {
      // Each side sends a burst of K messages, so every burst after the first
      // reply crosses the threshold.
      for (let i = 0; i < K; i++) {
        await recv(receiver, await send(sender, receiver, `${sender.name}${round}.${i}`));
        const s = await state(sender, receiver.name);
        const r = await state(receiver, sender.name);
        expect(r.recvEpoch).toBe(s.sendEpoch);
        expect(hex(await sha256(s.cks!))).toBe(hex(await sha256(r.ckr!)));
        // Until the receiver takes its own send step, both hold the same root key.
        if (s.sendEpoch > 0 && r.sendEpoch < r.recvEpoch) expect(hex(await sha256(s.rk))).toBe(hex(await sha256(r.rk)));
      }
      epochsSeen = (await state(alice, "bob")).sendEpoch;
      [sender, receiver] = [receiver, sender];
    }
    expect(epochsSeen).toBeGreaterThanOrEqual(6);
  });

  it("no send step happens before the peer's ratchet key arrives, however many messages", async () => {
    const { alice, bob } = await world({ ratchetEveryK: K });
    for (let i = 0; i < 2 * K + 2; i++) {
      const env = await send(alice, bob, `a${i}`);
      expect(env.epoch).toBe(0);
      expect(await recv(bob, env)).toBe(`a${i}`);
    }
  });

  it("first message, peer key arrival, then the threshold: K messages per chain before the next epoch", async () => {
    const { alice, bob } = await started(K);
    // Alice has sent 1 message on epoch 0; she steps when that count reaches K.
    const envs = await untilStep(alice, bob);
    expect(envs).toHaveLength(Math.max(K - 1, 0) + 1);
    for (const env of envs.slice(0, -1)) {
      expect(env.epoch).toBe(0);
      expect(env.kem).toBeUndefined();
    }
    const stepped = envs[envs.length - 1];
    expect(stepped).toMatchObject({ epoch: 2, n: 0, pn: Math.max(K, 1) });
    expect(stepped.kem).toBeDefined();
    for (const env of envs) await recv(bob, env);
    expect((await state(bob, "alice")).recvEpoch).toBe(2);
  });

  it("ratchet data rides on every message of a chain until the peer acknowledges it", async () => {
    const { alice, bob } = await world({ ratchetEveryK: K });
    // Highest epoch each side has received from the other: the acknowledgement.
    const acked = { alice: -1, bob: -1 };
    const r = rng(K);
    for (let i = 0; i < 300; i++) {
      // Alice opens the session; after that either side may send.
      const [from, to] = i === 0 || r() < 0.5 ? [alice, bob] : [bob, alice];
      const env = await send(from, to, "x");
      const peerSaw = acked[to.name as "alice" | "bob"];
      if (env.epoch === 0) {
        // Epoch 0 carries the init header instead, until Bob's first reply arrives.
        expect(Boolean(env.init)).toBe(acked.alice < 1);
      } else {
        // Acknowledged exactly when the receiver has already sent a newer epoch we received.
        expect(Boolean(env.kem)).toBe(!(acked[from.name as "alice" | "bob"] > env.epoch));
      }
      await recv(to, env);
      acked[to.name as "alice" | "bob"] = Math.max(peerSaw, env.epoch);
    }
  });

  it("duplicated and reordered messages across an epoch boundary", async () => {
    const { alice, bob } = await started(K);
    const envs = [...(await untilStep(alice, bob))];
    for (let i = 0; i < 3; i++) envs.push(await send(alice, bob, `t${i}`));
    for (const env of shuffle(envs, rng(K + 1))) await recv(bob, env);
    expect((await state(bob, "alice")).skipped).toHaveLength(0);
    for (const env of envs) await expectRejected(bob, env, ["DUPLICATE", "STALE_EPOCH"]);
  });

  it("a lost ratchet message: later messages of the epoch still open, and the retransmission opens too", async () => {
    const { alice, bob } = await started(K);
    const envs = await untilStep(alice, bob);
    const lost = envs[envs.length - 1]; // opens epoch 2 and carries the KEM ciphertext
    for (const env of envs.slice(0, -1)) await recv(bob, env);
    const next = await send(alice, bob, "after the loss");
    expect(next.epoch).toBe(2);
    expect(next.kem).toEqual(lost.kem);
    expect(await recv(bob, next)).toBe("after the loss");
    expect(await recv(bob, lost)).toBe(`s${envs.length - 1}`);
    await expectRejected(bob, lost, "DUPLICATE");
  });

  it("restart after the state was saved but before the socket send", async () => {
    const { dir, alice, bob } = await started(K);
    const envs = await untilStep(alice, bob);
    const unsent = envs.pop()!; // saved by encrypt(), never sent: the tab closed
    for (const env of envs) await recv(bob, env);
    const restarted: Party = { ...alice, sm: managerFor(alice, dir, { ratchetEveryK: K }) };
    const env = await send(restarted, bob, "after restart");
    // Same epoch and ratchet data, next counter: the saved step is not redone.
    expect(env).toMatchObject({ epoch: unsent.epoch, n: unsent.n + 1 });
    expect(env.kem).toEqual(unsent.kem);
    expect(await recv(bob, env)).toBe("after restart");
    // The outbox resends the saved envelope later; it still opens exactly once.
    expect(await recv(bob, unsent)).toBe(`s${envs.length}`);
    await expectRejected(bob, unsent, "DUPLICATE");
  });

  it("wrong suite and wrong key or ciphertext lengths are rejected before any state change", async () => {
    const { alice, bob } = await started(K);
    const env = (await untilStep(alice, bob)).pop()!;
    const kem = env.kem!;
    const bad: EnvelopeV1[] = [
      { ...copy(env), suite: "mlkem768" } as unknown as EnvelopeV1,
      { ...copy(env), kem: { ...kem, ct: resizeB64(kem.ct, 1088) } },
      { ...copy(env), kem: { ...kem, ek: resizeB64(kem.ek, 1184) } },
      { ...copy(env), kem: { ...kem, ct: resizeB64(kem.ct, 1567) } },
    ];
    for (const v of bad) await expectRejected(bob, v, "MALFORMED");
  });

  it("a tampered ratchet ciphertext or key fails authentication, and the real message still opens", async () => {
    const { alice, bob } = await started(K);
    const envs = await untilStep(alice, bob);
    for (const env of envs.slice(0, -1)) await recv(bob, env);
    const env = envs[envs.length - 1];
    await expectRejected(bob, { ...copy(env), kem: { ...env.kem!, ct: flipB64(env.kem!.ct, 77, 2) } }, "AUTH_FAILED");
    await expectRejected(bob, { ...copy(env), kem: { ...env.kem!, ek: flipB64(env.kem!.ek, 9, 4) } }, "AUTH_FAILED");
    expect(await recv(bob, env)).toBe(`s${envs.length - 1}`);
  });

  it("old keys are not restored by a failed or stale packet", async () => {
    const { alice, bob } = await started(K);
    const old = await untilStep(alice, bob);
    for (const env of old) await recv(bob, env);
    // Move both sides two epochs further.
    for (let i = 0; i < 2; i++) {
      for (const env of await untilStep(bob, alice)) await recv(alice, env);
      for (const env of await untilStep(alice, bob)) await recv(bob, env);
    }
    const before = await state(bob, "alice");
    // Stale packets (already opened, older epochs) and a forged one change nothing.
    for (const env of old) await expectRejected(bob, env, ["DUPLICATE", "STALE_EPOCH"]);
    const live = await send(alice, bob, "live");
    await expectRejected(bob, { ...copy(live), body: flipB64(live.body, 2) }, "AUTH_FAILED");
    const after = await state(bob, "alice");
    expect(after.recvEpoch).toBe(before.recvEpoch);
    expect(hex(await sha256(after.rk))).toBe(hex(await sha256(before.rk)));
    expect(await recv(bob, live)).toBe("live");
  });
});

describe("counter boundaries (wire fields stay 32-bit)", () => {
  it("n, pn and epoch above 2^32 - 1 are malformed", async () => {
    const { alice, bob } = await started(1);
    const env = await send(alice, bob, "x");
    for (const field of ["n", "pn", "epoch"] as const) {
      await expectRejected(bob, { ...copy(env), [field]: 2 ** 32 }, "MALFORMED");
    }
  });

  it("the sending chain stops at n = 2^32 - 1 instead of wrapping", async () => {
    const { alice, bob } = await world();
    await send(alice, bob, "a0"); // no reply, so no send step can reset n
    const rec = (await alice.store.load("bob"))!;
    rec.session!.ns = 0xffffffff - 1;
    await alice.store.save("bob", rec);
    const last = await send(alice, bob, "last");
    expect(last.n).toBe(0xffffffff - 1);
    await expect(send(alice, bob, "one too many")).rejects.toThrow("sending chain exhausted");
  });

  it("the epoch counter stops at 2^32 - 1 instead of wrapping", async () => {
    const { alice, bob } = await started(1);
    const rec = (await alice.store.load("bob"))!;
    // Pretend the peer's last epoch was the largest odd u32: the next send step would need 2^32.
    rec.session!.recvEpoch = 0xffffffff;
    await alice.store.save("bob", rec);
    const before = alice.store.raw("bob");
    await expect(send(alice, bob, "x")).rejects.toThrow("epoch space exhausted");
    expect(alice.store.raw("bob")).toBe(before);
  });
});
