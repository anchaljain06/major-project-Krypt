/**
 * File-transfer crypto (spec 15): manifest parsing, chunk AAD, nonces and
 * per-chunk AES-256-GCM, including the negative cases from plan Phase E.
 */
import { describe, expect, it } from "vitest";
import { compareBytes, fromBase64url, toBase64url } from "../src/crypto/encoding";
import {
  FILE_CHUNK_SIZE,
  MAX_CHUNK_COUNT,
  MAX_FILE_BYTES,
  chunkAad,
  chunkLength,
  chunkNonce,
  createManifest,
  parseManifest,
  safeFileName,
  u64,
  type FileManifestV1,
} from "../src/crypto/fileManifest";
import { decryptFileChunk, encryptFileChunk, importFileKey } from "../src/crypto/fileTransfer";

const m = (size = 2.5 * FILE_CHUNK_SIZE): FileManifestV1 => createManifest("report.pdf", "application/pdf", size);

describe("manifest", () => {
  it("round-trips and computes the chunk count", () => {
    const a = m();
    expect(parseManifest(JSON.parse(JSON.stringify(a)))).toEqual(a);
    expect(a.chunkCount).toBe(3);
    expect([0, 1, 2].map((i) => chunkLength(a, i))).toEqual([FILE_CHUNK_SIZE, FILE_CHUNK_SIZE, FILE_CHUNK_SIZE / 2]);
  });

  it("represents a zero-byte file as one empty chunk", () => {
    const z = m(0);
    expect(z.chunkCount).toBe(1);
    expect(chunkLength(z, 0)).toBe(0);
  });

  it("gives every transfer its own id, key and nonce prefix", () => {
    const a = m();
    const b = m();
    expect(a.transferId).not.toBe(b.transferId);
    expect(a.fileKey).not.toBe(b.fileKey);
    expect(fromBase64url(a.fileKey)).toHaveLength(32);
    expect(fromBase64url(a.noncePrefix)).toHaveLength(4);
  });

  it.each<[string, (x: Record<string, unknown>) => void]>([
    ["wrong version", (x) => (x.v = 2)],
    ["wrong protocol", (x) => (x.protocol = "KRYPT-FILE-V2")],
    ["short transferId", (x) => (x.transferId = toBase64url(new Uint8Array(15)))],
    ["empty name", (x) => (x.name = "")],
    ["negative size", (x) => (x.size = -1)],
    ["fractional size", (x) => (x.size = 1.5)],
    ["unsafe size", (x) => (x.size = 2 ** 53)],
    ["file too large", (x) => ((x.size = MAX_FILE_BYTES + 1), (x.chunkCount = Math.ceil((MAX_FILE_BYTES + 1) / FILE_CHUNK_SIZE)))],
    ["chunk count disagrees", (x) => (x.chunkCount = 4)],
    ["chunk size too small", (x) => (x.chunkSize = 1024)],
    ["31-byte key", (x) => (x.fileKey = toBase64url(new Uint8Array(31)))],
    ["5-byte nonce prefix", (x) => (x.noncePrefix = toBase64url(new Uint8Array(5)))],
    ["padded base64", (x) => (x.fileKey = `${x.fileKey}=`)],
  ])("rejects %s", (_name, mutate) => {
    const x = JSON.parse(JSON.stringify(m())) as Record<string, unknown>;
    mutate(x);
    expect(() => parseManifest(x)).toThrow(/malformed/);
  });

  it("caps the chunk count", () => {
    expect(MAX_CHUNK_COUNT * FILE_CHUNK_SIZE).toBeGreaterThanOrEqual(MAX_FILE_BYTES);
  });
});

describe("nonce and AAD", () => {
  it("nonce = prefix ‖ uint64_be(counter)", () => {
    const a = m();
    const n = chunkNonce(a, 2 ** 32 - 1);
    expect(n).toHaveLength(12);
    expect(compareBytes(n.subarray(0, 4), fromBase64url(a.noncePrefix))).toBe(0);
    expect(Array.from(n.subarray(4))).toEqual([0, 0, 0, 0, 255, 255, 255, 255]);
    expect(Array.from(u64(2 ** 40 + 1))).toEqual([0, 0, 1, 0, 0, 0, 0, 1]);
    expect(() => chunkNonce(a, 2 ** 32)).toThrow();
  });

  it("every field changes the AAD", () => {
    const a = m();
    const base = chunkAad(a, "alice", "bob", 1, 7);
    const variants = [
      chunkAad({ ...a, transferId: m().transferId }, "alice", "bob", 1, 7),
      chunkAad(a, "alicf", "bob", 1, 7),
      chunkAad(a, "alice", "bob2", 1, 7),
      chunkAad(a, "bob", "alice", 1, 7),
      chunkAad(a, "alice", "bob", 0, 7),
      chunkAad(a, "alice", "bob", 1, 8),
      chunkAad({ ...a, size: a.size - 1 }, "alice", "bob", 1, 7),
      chunkAad({ ...a, chunkCount: 4, size: 3.5 * FILE_CHUNK_SIZE }, "alice", "bob", 1, 7),
    ];
    for (const v of variants) expect(compareBytes(v, base)).not.toBe(0);
  });
});

describe("chunk encryption", () => {
  const setup = async () => {
    const a = m();
    const key = await importFileKey(a.fileKey);
    const plaintext = new Uint8Array(chunkLength(a, 2)).map((_, i) => (i * 31) & 255);
    const seal = (index: number, counter: number, pt = plaintext) =>
      encryptFileChunk({ fileKey: key, nonce: chunkNonce(a, counter), plaintext: pt, aad: chunkAad(a, "alice", "bob", index, counter) });
    const open = (ct: Uint8Array, index: number, counter: number, manifest = a, from = "alice", to = "bob") =>
      decryptFileChunk({ fileKey: key, nonce: chunkNonce(manifest, counter), ciphertextAndTag: ct, aad: chunkAad(manifest, from, to, index, counter) });
    return { a, key, plaintext, seal, open };
  };

  it("round-trips; output is plaintext plus a 16-byte tag", async () => {
    const { plaintext, seal, open } = await setup();
    const ct = await seal(2, 5);
    expect(ct.length).toBe(plaintext.length + 16);
    expect(compareBytes(await open(ct, 2, 5), plaintext)).toBe(0);
  });

  it("encrypts an empty chunk", async () => {
    const z = m(0);
    const key = await importFileKey(z.fileKey);
    const ct = await encryptFileChunk({ fileKey: key, nonce: chunkNonce(z, 0), plaintext: new Uint8Array(0), aad: chunkAad(z, "a", "b", 0, 0) });
    expect(ct).toHaveLength(16);
    expect(await decryptFileChunk({ fileKey: key, nonce: chunkNonce(z, 0), ciphertextAndTag: ct, aad: chunkAad(z, "a", "b", 0, 0) })).toHaveLength(0);
  });

  it("rejects a changed chunk, tag, index, counter, transfer, sender or recipient", async () => {
    const { a, seal, open } = await setup();
    const ct = await seal(2, 5);
    const flipped = (i: number) => {
      const c = ct.slice();
      c[i] ^= 1;
      return c;
    };
    await expect(open(flipped(0), 2, 5)).rejects.toThrow();
    await expect(open(flipped(ct.length - 1), 2, 5)).rejects.toThrow();
    await expect(open(ct.subarray(0, ct.length - 1), 2, 5)).rejects.toThrow();
    await expect(open(ct.subarray(0, 15), 2, 5)).rejects.toThrow(/truncated/);
    await expect(open(ct, 1, 5)).rejects.toThrow();
    await expect(open(ct, 2, 6)).rejects.toThrow();
    await expect(open(ct, 2, 5, { ...a, transferId: m().transferId })).rejects.toThrow();
    await expect(open(ct, 2, 5, a, "mallory")).rejects.toThrow();
    await expect(open(ct, 2, 5, a, "alice", "carol")).rejects.toThrow();
  });

  it("does not decrypt under another transfer's key", async () => {
    const { seal } = await setup();
    const ct = await seal(2, 5);
    const other = m();
    const otherKey = await importFileKey(other.fileKey);
    await expect(
      decryptFileChunk({ fileKey: otherKey, nonce: chunkNonce(other, 5), ciphertextAndTag: ct, aad: chunkAad(other, "alice", "bob", 2, 5) }),
    ).rejects.toThrow();
  });
});

describe("safeFileName", () => {
  it.each([
    ["../../etc/passwd", "_.._etc_passwd"],
    ["C:\\Windows\\evil.exe", "C__Windows_evil.exe"],
    ["report\u202Efdp.exe", "reportfdp.exe"],
    ["line\nbreak.txt", "linebreak.txt"],
    ["...", "download"],
    ["  ", "download"],
    ["photo.jpg", "photo.jpg"],
  ])("%j -> %j", (input, out) => {
    expect(safeFileName(input)).toBe(out);
  });
});
