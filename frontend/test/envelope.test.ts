import { describe, expect, it } from "vitest";
import { LABELS, lp, u32 } from "../src/crypto/encoding";
import {
  decodeBinaryEnvelope,
  encodeBinaryEnvelope,
  headerAad,
  headerBytes,
  parseEnvelope,
  toWire,
  type Envelope,
} from "../src/crypto/envelope";
import { DecryptError } from "../src/crypto/errors";

const bytes = (n: number, fill = 1) => new Uint8Array(n).fill(fill);

function sample(withKem = true): Envelope {
  return {
    header: {
      v: 1,
      suite: "mlkem768",
      sessionId: bytes(32, 7),
      from: "alice",
      to: "bob",
      contentType: "text",
      epoch: withKem ? 2 : 0,
      n: 5,
      pn: 3,
      kem: withKem ? { ct: bytes(1088, 2), ek: bytes(1184, 3) } : null,
      init: withKem
        ? null
        : { spkId: 9, opkId: null, ct1: bytes(1568, 4), ct2: null, ek: bytes(1184, 5), sig: bytes(4627, 6) },
    },
    body: bytes(40, 8),
  };
}

const code = (fn: () => unknown) => {
  try {
    fn();
    return "OK";
  } catch (e) {
    expect(e).toBeInstanceOf(DecryptError);
    return (e as DecryptError).code;
  }
};

describe("canonical header bytes", () => {
  it("match the spec layout field by field", () => {
    const env = sample();
    const h = env.header;
    const expected = lp(
      u32(1),
      "mlkem768",
      h.sessionId,
      "alice",
      "bob",
      "text",
      u32(2),
      u32(5),
      u32(3),
      lp(h.kem!.ct, h.kem!.ek),
      new Uint8Array(0),
    );
    expect(headerBytes(h)).toEqual(expected);
    expect(headerAad(h)).toEqual(lp(LABELS.aad, expected));
  });

  it("init field encodes an absent OPK as empty fields", () => {
    const h = sample(false).header;
    const i = h.init!;
    const initField = lp(u32(9), new Uint8Array(0), i.ct1, new Uint8Array(0), i.ek, i.sig);
    expect(headerBytes(h)).toEqual(
      lp(u32(1), "mlkem768", h.sessionId, "alice", "bob", "text", u32(0), u32(5), u32(3), new Uint8Array(0), initField),
    );
  });
});

describe("JSON and binary codecs", () => {
  for (const withKem of [true, false]) {
    it(`round-trip (${withKem ? "kem" : "init"})`, () => {
      const env = sample(withKem);
      const wire = toWire(env);
      expect(parseEnvelope(JSON.stringify(wire))).toEqual(env);
      expect(decodeBinaryEnvelope(encodeBinaryEnvelope(env))).toEqual(env);
      expect(withKem ? "kem" in wire : "init" in wire).toBe(true);
      expect(withKem ? "init" in wire : "kem" in wire).toBe(false);
    });
  }

  it("rejects unknown, missing and mistyped keys", () => {
    const w = toWire(sample()) as unknown as Record<string, unknown>;
    expect(code(() => parseEnvelope({ ...w, extra: 1 }))).toBe("MALFORMED");
    const { n: _n, ...noN } = w;
    void _n;
    expect(code(() => parseEnvelope(noN))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, n: "5" }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, n: 1.5 }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, n: -1 }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, epoch: 2 ** 32 }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, kem: null }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, v: 2 }))).toBe("UNSUPPORTED_VERSION");
    expect(code(() => parseEnvelope({ ...w, suite: "kyber" }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope("{not json"))).toBe("MALFORMED");
    expect(code(() => parseEnvelope([]))).toBe("MALFORMED");
  });

  it("rejects wrong lengths, padding and structural violations", () => {
    const w = toWire(sample());
    expect(code(() => parseEnvelope({ ...w, sessionId: w.sessionId.slice(0, -2) }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, body: w.body + "=" }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, kem: { ...w.kem!, ek: w.kem!.ct } }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, epoch: 0 }))).toBe("MALFORMED"); // kem in epoch 0
    expect(code(() => parseEnvelope({ ...w, from: "" }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, from: "x".repeat(65) }))).toBe("MALFORMED");
    expect(code(() => parseEnvelope({ ...w, from: "\uD800" }))).toBe("MALFORMED"); // lone surrogate
    expect(code(() => parseEnvelope({ ...w, body: "AAAA" }))).toBe("MALFORMED"); // shorter than a tag
    const i = toWire(sample(false));
    expect(code(() => parseEnvelope({ ...i, epoch: 2 }))).toBe("MALFORMED"); // init outside epoch 0
    expect(code(() => parseEnvelope({ ...i, init: { ...i.init!, opkId: 3 } }))).toBe("MALFORMED"); // opkId without ct2
    expect(code(() => parseEnvelope({ ...i, init: { ...i.init!, spkId: 0 } }))).toBe("MALFORMED");
  });

  it("binary decoder rejects truncation, trailing bytes and bad UTF-8", () => {
    const b = encodeBinaryEnvelope(sample());
    expect(code(() => decodeBinaryEnvelope(b.subarray(0, b.length - 1)))).toBe("MALFORMED");
    expect(code(() => decodeBinaryEnvelope(new Uint8Array([...b, 0])))).toBe("MALFORMED");
    const h = sample().header;
    const badName = lp(
      lp(u32(1), "mlkem768", h.sessionId, new Uint8Array([0xff]), "bob", "text", u32(2), u32(5), u32(3), lp(h.kem!.ct, h.kem!.ek), new Uint8Array(0)),
      bytes(20),
    );
    expect(code(() => decodeBinaryEnvelope(badName))).toBe("MALFORMED");
  });
});
