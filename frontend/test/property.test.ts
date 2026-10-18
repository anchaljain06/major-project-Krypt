/**
 * Property tests (fast-check):
 *  1. decrypt(encrypt(m)) = m for arbitrary plaintexts and content types.
 *  2. Any single-bit flip anywhere in a serialized envelope (JSON text or
 *     binary form) is rejected with a typed DecryptError and leaves every
 *     store unchanged; the original still decrypts afterwards.
 */
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { decodeBinaryEnvelope, encodeBinaryEnvelope, parseEnvelope, toWire, type EnvelopeV1 } from "../src/crypto/envelope";
import type { KemSuite } from "../src/crypto/pq";
import { recv, send, world, type Party } from "./helpers";

async function rejectsUnchanged(p: Party, input: unknown): Promise<boolean> {
  const before = p.store.raw("alice");
  const pk = p.prekeys.fingerprint();
  try {
    await p.sm.decrypt(input);
    return false;
  } catch (e) {
    return (e as Error).name === "DecryptError" && p.store.raw("alice") === before && p.prekeys.fingerprint() === pk;
  }
}

function flipJson(text: string, index: number, bit: number): string {
  const i = index % text.length;
  return text.slice(0, i) + String.fromCharCode(text.charCodeAt(i) ^ (1 << bit)) + text.slice(i + 1);
}

// A content type is any 1-64 byte UTF-8 string without lone surrogates.
const contentTypeArb = fc
  .string({ unit: "grapheme", minLength: 1, maxLength: 16 })
  .filter((s) => {
    const n = new TextEncoder().encode(s).length;
    return n >= 1 && n <= 64;
  });

const suite: KemSuite = "mlkem1024";
describe(`[${suite}] properties`, () => {
  it("decrypt(encrypt(m)) = m, in both directions", async () => {
    const { alice, bob } = await world({ suite });
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 2048 }), contentTypeArb, fc.boolean(), async (m, ct, aliceSends) => {
        const [from, to] = aliceSends ? [alice, bob] : [bob, alice];
        if (!aliceSends && !(await bob.sm.getStatus("alice"))) return; // Bob can only reply once a session exists
        const env = await from.sm.encrypt(to.name, m, ct);
        const r = await to.sm.decrypt(JSON.parse(JSON.stringify(env)));
        expect(r.plaintext).toEqual(m);
        expect(r.contentType).toBe(ct);
      }),
      { numRuns: 150 },
    );
  });

  for (const kind of ["init (epoch 0)", "ratchet (epoch 2)"] as const) {
    it(`single-bit flips in the JSON text of a ${kind} message are rejected`, async () => {
      const { alice, bob } = await world({ suite });
      let env: EnvelopeV1;
      if (kind === "init (epoch 0)") {
        env = await send(alice, bob, "target");
      } else {
        await recv(bob, await send(alice, bob, "a0"));
        await recv(alice, await send(bob, alice, "b0"));
        env = await send(alice, bob, "target");
        expect(env.kem).toBeDefined();
      }
      const text = JSON.stringify(env);
      await fc.assert(
        fc.asyncProperty(fc.nat({ max: text.length - 1 }), fc.integer({ min: 0, max: 7 }), async (i, bit) => {
          expect(await rejectsUnchanged(bob, flipJson(text, i, bit))).toBe(true);
        }),
        { numRuns: 250 },
      );
      expect(await recv(bob, text)).toBe("target");
    });
  }

  it("every bit of every structural JSON character (outside long base64 values) is checked exhaustively", async () => {
    const { alice, bob } = await world({ suite });
    await recv(bob, await send(alice, bob, "a0"));
    await recv(alice, await send(bob, alice, "b0"));
    const env = await send(alice, bob, "target");
    const text = JSON.stringify(env);
    // Positions inside base64 strings longer than 64 chars are covered by the random test above.
    const skip = new Set<number>();
    for (const m of text.matchAll(/"([A-Za-z0-9_-]{65,})"/g)) {
      for (let k = m.index! + 1; k < m.index! + 1 + m[1].length; k++) skip.add(k);
    }
    let checked = 0;
    for (let i = 0; i < text.length; i++) {
      if (skip.has(i)) continue;
      for (let bit = 0; bit < 8; bit++) {
        expect(await rejectsUnchanged(bob, flipJson(text, i, bit)), `char ${i} bit ${bit}`).toBe(true);
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(800);
    expect(await recv(bob, text)).toBe("target");
  });

  it("single-bit flips anywhere in the binary envelope are rejected", async () => {
    const { alice, bob } = await world({ suite });
    await recv(bob, await send(alice, bob, "a0"));
    await recv(alice, await send(bob, alice, "b0"));
    const env = await send(alice, bob, "target");
    const bin = encodeBinaryEnvelope(parseEnvelope(env));
    await fc.assert(
      fc.asyncProperty(fc.nat({ max: bin.length * 8 - 1 }), async (pos) => {
        const flipped = bin.slice();
        flipped[pos >> 3] ^= 1 << (pos & 7);
        let wire: unknown;
        try {
          wire = toWire(decodeBinaryEnvelope(flipped));
        } catch (e) {
          expect((e as Error).name).toBe("DecryptError"); // rejected by the parser
          return;
        }
        expect(await rejectsUnchanged(bob, wire)).toBe(true);
      }),
      { numRuns: 300 },
    );
    expect(await recv(bob, toWire(decodeBinaryEnvelope(bin)))).toBe("target");
  });
});
