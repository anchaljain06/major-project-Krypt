import { describe, expect, it } from "vitest";
import { LABELS, lp, u32 } from "../src/crypto/encoding";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  hkdf,
  hmacSha256,
  kdfChain,
  kdfHandshake,
  kdfRoot,
  messageKeyAndIv,
  rootContext,
  sha256,
} from "../src/crypto/kdf";

const h = (s: string) => new Uint8Array(Buffer.from(s.replace(/\s+/g, ""), "hex"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const range = (from: number, to: number) => Uint8Array.from({ length: to - from + 1 }, (_, i) => from + i);

describe("HKDF-SHA-256 (RFC 5869 appendix A)", () => {
  it("test case 1", async () => {
    const okm = await hkdf(range(0x00, 0x0c), new Uint8Array(22).fill(0x0b), range(0xf0, 0xf9), 42);
    expect(hex(okm)).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  });

  it("test case 2 (long inputs)", async () => {
    const okm = await hkdf(range(0x60, 0xaf), range(0x00, 0x4f), range(0xb0, 0xff), 82);
    expect(hex(okm)).toBe(
      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
        "cc30c58179ec3e87c14c01d5c1f3434f1d87",
    );
  });

  it("test case 3 (empty salt and info)", async () => {
    const okm = await hkdf(new Uint8Array(0), new Uint8Array(22).fill(0x0b), new Uint8Array(0), 42);
    expect(hex(okm)).toBe("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
  });

  it("empty salt equals 32 zero bytes", async () => {
    const ikm = new Uint8Array(32).fill(7);
    const a = await hkdf(new Uint8Array(0), ikm, new Uint8Array(0), 32);
    const b = await hkdf(new Uint8Array(32), ikm, new Uint8Array(0), 32);
    expect(hex(a)).toBe(hex(b));
  });

  it("rejects invalid lengths", async () => {
    await expect(hkdf(new Uint8Array(0), new Uint8Array(1), new Uint8Array(0), 0)).rejects.toThrow();
    await expect(hkdf(new Uint8Array(0), new Uint8Array(1), new Uint8Array(0), 255 * 32 + 1)).rejects.toThrow();
  });
});

describe("HMAC-SHA-256 (RFC 4231) and SHA-256", () => {
  it("RFC 4231 test case 1", async () => {
    const mac = await hmacSha256(new Uint8Array(20).fill(0x0b), new TextEncoder().encode("Hi There"));
    expect(hex(mac)).toBe("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  });
  it("RFC 4231 test case 2", async () => {
    const mac = await hmacSha256(new TextEncoder().encode("Jefe"), new TextEncoder().encode("what do ya want for nothing?"));
    expect(hex(mac)).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  });
  it("SHA-256('abc')", async () => {
    expect(hex(await sha256(new TextEncoder().encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("Krypt KDFs follow the spec formulas exactly", () => {
  const ck = h("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

  it("kdfChain: mk = HMAC(ck, 0x01), ck' = HMAC(ck, 0x02)", async () => {
    const { mk, ck: next } = await kdfChain(ck);
    expect(hex(mk)).toBe(hex(await hmacSha256(ck, new Uint8Array([1]))));
    expect(hex(next)).toBe(hex(await hmacSha256(ck, new Uint8Array([2]))));
    expect(hex(mk)).not.toBe(hex(next));
  });

  it("messageKeyAndIv = HKDF(0^32, mk, 'Krypt-MK', 44) split 32/12", async () => {
    const { key, iv } = await messageKeyAndIv(ck);
    const okm = await hkdf(new Uint8Array(32), ck, new TextEncoder().encode("Krypt-MK"), 44);
    expect(key.length).toBe(32);
    expect(iv.length).toBe(12);
    expect(hex(key) + hex(iv)).toBe(hex(okm));
  });

  it("kdfRoot = HKDF(rk, ss, lp('Krypt-RK', ctx), 64) and ctx binds epoch, H(ek), H(ct)", async () => {
    const rk = new Uint8Array(32).fill(1);
    const ss = new Uint8Array(32).fill(2);
    const ek = new Uint8Array(1184).fill(3);
    const ct = new Uint8Array(1088).fill(4);
    const ctx = await rootContext(5, ek, ct);
    expect(hex(ctx)).toBe(hex(lp(u32(5), await sha256(ek), await sha256(ct))));
    const out = await kdfRoot(rk, ss, ctx);
    const okm = await hkdf(rk, ss, lp(LABELS.root, ctx), 64);
    expect(hex(out.rk) + hex(out.ck)).toBe(hex(okm));
    // Any change in the context changes both outputs.
    const other = await kdfRoot(rk, ss, await rootContext(6, ek, ct));
    expect(hex(other.rk)).not.toBe(hex(out.rk));
    expect(hex(other.ck)).not.toBe(hex(out.ck));
  });

  it("kdfHandshake = HKDF(0^32, lp(ss1, ss2), lp('Krypt-X3K', H(T)), 64)", async () => {
    const ss1 = new Uint8Array(32).fill(9);
    const hT = new Uint8Array(32).fill(8);
    const out = await kdfHandshake(ss1, new Uint8Array(0), hT);
    const okm = await hkdf(new Uint8Array(32), lp(ss1, new Uint8Array(0)), lp("Krypt-X3K", hT), 64);
    expect(hex(out.rk) + hex(out.ck)).toBe(hex(okm));
  });

  it("rejects wrong key lengths", async () => {
    await expect(kdfChain(new Uint8Array(31))).rejects.toThrow();
    await expect(messageKeyAndIv(new Uint8Array(33))).rejects.toThrow();
    await expect(kdfRoot(new Uint8Array(32), new Uint8Array(16), new Uint8Array(0))).rejects.toThrow();
  });
});

describe("AES-256-GCM wrapper", () => {
  it("round-trips and rejects any change to ciphertext, tag or AAD", async () => {
    const key = new Uint8Array(32).fill(1);
    const iv = new Uint8Array(12).fill(2);
    const pt = new TextEncoder().encode("hello");
    const aad = new TextEncoder().encode("hdr");
    const body = await aesGcmEncrypt(key, iv, pt, aad);
    expect(body.length).toBe(pt.length + 16);
    expect(new TextDecoder().decode(await aesGcmDecrypt(key, iv, body, aad))).toBe("hello");
    for (const i of [0, body.length - 1]) {
      const t = body.slice();
      t[i] ^= 1;
      await expect(aesGcmDecrypt(key, iv, t, aad)).rejects.toThrow();
    }
    await expect(aesGcmDecrypt(key, iv, body, new TextEncoder().encode("hdR"))).rejects.toThrow();
  });
});
