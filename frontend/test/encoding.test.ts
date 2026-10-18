import { describe, expect, it } from "vitest";
import { fromBase64, toBase64 } from "@krypt/shared";
import {
  compareBytes,
  ctEqual,
  fromBase64url,
  lp,
  readU32,
  toBase64url,
  u32,
  unlp,
  utf8,
} from "../src/crypto/encoding";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("lp encoding", () => {
  it("prefixes every field with a 4-byte big-endian length", () => {
    expect(hex(lp("ab", new Uint8Array([1, 2, 3])))).toBe("00000002" + "6162" + "00000003" + "010203");
    expect(hex(lp(new Uint8Array(0)))).toBe("00000000");
  });

  it("is injective where raw concatenation is not", () => {
    expect(hex(lp("ab", "c"))).not.toBe(hex(lp("a", "bc")));
    expect(hex(lp("", "a"))).not.toBe(hex(lp("a", "")));
  });

  it("round-trips through unlp and rejects truncation and trailing bytes", () => {
    const enc = lp("x", u32(7), new Uint8Array(300));
    const [a, b, c] = unlp(enc, 3);
    expect(new TextDecoder().decode(a)).toBe("x");
    expect(readU32(b)).toBe(7);
    expect(c.length).toBe(300);
    expect(() => unlp(enc.subarray(0, enc.length - 1))).toThrow();
    expect(() => unlp(new Uint8Array([0, 0, 0]))).toThrow();
    expect(() => unlp(enc, 2)).toThrow();
  });

  it("u32 rejects out-of-range values", () => {
    expect(hex(u32(0xdeadbeef))).toBe("deadbeef");
    expect(() => u32(-1)).toThrow();
    expect(() => u32(2 ** 32)).toThrow();
    expect(() => u32(1.5)).toThrow();
  });
});

describe("base64url", () => {
  // RFC 4648 section 10 test vectors (base64url alphabet, padding removed).
  const vectors: [string, string][] = [
    ["", ""],
    ["f", "Zg"],
    ["fo", "Zm8"],
    ["foo", "Zm9v"],
    ["foob", "Zm9vYg"],
    ["fooba", "Zm9vYmE"],
    ["foobar", "Zm9vYmFy"],
  ];
  it.each(vectors)("encodes %j as %j", (plain, enc) => {
    expect(toBase64url(utf8(plain))).toBe(enc);
    expect(new TextDecoder().decode(fromBase64url(enc))).toBe(plain);
  });

  it("uses the URL-safe alphabet", () => {
    expect(toBase64url(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
  });

  it("round-trips random data of every length mod 3", () => {
    for (let len = 0; len < 64; len++) {
      const b = crypto.getRandomValues(new Uint8Array(len));
      expect(hex(fromBase64url(toBase64url(b)))).toBe(hex(b));
    }
  });

  it("rejects padding, whitespace, foreign characters, bad length and non-canonical bits", () => {
    // "Zh", "Zm9" and "Zm-" carry non-zero unused bits; the canonical forms are "Zg" and "Zm8".
    for (const bad of ["Zg==", "Zm9v YmFy", "Zm9v+mFy", "Zm9v/mFy", "Z", "Zm9vY", "Zh", "Zm9", "Zm-", "é"]) {
      expect(() => fromBase64url(bad), bad).toThrow();
    }
  });
});

// The identityKey JSON and the local stores use @krypt/shared standard base64;
// the app relies on its decoder being strict, so that is pinned here too.
describe("standard base64 (@krypt/shared)", () => {
  it("round-trips and rejects non-canonical input", () => {
    const b = new Uint8Array([0xfb, 0xff, 0x01]);
    expect(toBase64(b)).toBe("+/8B");
    expect(hex(fromBase64("+/8B"))).toBe("fbff01");
    expect(hex(fromBase64("Zg=="))).toBe("66");
    expect(() => fromBase64("Zg")).toThrow();
    expect(() => fromBase64("Zh==")).toThrow();
    expect(() => fromBase64("-_8B")).toThrow();
  });
});

describe("comparisons", () => {
  it("ctEqual", () => {
    expect(ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(ctEqual(new Uint8Array([1]), new Uint8Array([1, 0]))).toBe(false);
  });
  it("compareBytes is lexicographic and unsigned", () => {
    expect(compareBytes(new Uint8Array([1, 255]), new Uint8Array([2, 0]))).toBe(-1);
    expect(compareBytes(new Uint8Array([0x80]), new Uint8Array([0x7f]))).toBe(1);
    expect(compareBytes(new Uint8Array([1]), new Uint8Array([1, 0]))).toBe(-1);
    expect(compareBytes(new Uint8Array([4, 5]), new Uint8Array([4, 5]))).toBe(0);
  });
});
