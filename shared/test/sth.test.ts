import { ml_dsa44, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { toHex, utf8 } from "../src/bytes.ts";
import {
  TREE_HEAD_SIZE,
  cosignTreeHead,
  cosignatureFromJson,
  cosignatureMessage,
  cosignatureToJson,
  decodeTreeHead,
  encodeTreeHead,
  logIdFromPublicKey,
  signTreeHead,
  sthFromJson,
  sthToJson,
  verifyCosignature,
  verifyTreeHead,
  type TreeHead,
} from "../src/sth.ts";
import { flipBit } from "./helpers.ts";

const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(9));
const witnessKey = ml_dsa44.keygen(new Uint8Array(32).fill(10));
const logSign = (m: Uint8Array) => ml_dsa87.sign(m, logKey.secretKey);
const logVerify = (m: Uint8Array, s: Uint8Array) => ml_dsa87.verify(s, m, logKey.publicKey);
const witSign = (m: Uint8Array) => ml_dsa44.sign(m, witnessKey.secretKey);
const witVerify = (m: Uint8Array, s: Uint8Array) => ml_dsa44.verify(s, m, witnessKey.publicKey);

const head: TreeHead = { treeSize: 42, rootHash: new Uint8Array(32).fill(0x5a), timestampMs: 1_760_000_000_000 };

describe("tree head encoding", () => {
  it("is KRYPT-STH-v1 || u64 size || root || u64 timestamp", () => {
    const enc = encodeTreeHead(head);
    expect(enc.length).toBe(TREE_HEAD_SIZE);
    expect(toHex(enc)).toBe(
      toHex(utf8("KRYPT-STH-v1")) + "000000000000002a" + "5a".repeat(32) + "00000199c82cc000",
    );
  });

  it("round-trips", () => {
    fc.assert(
      fc.property(
        fc.nat(Number.MAX_SAFE_INTEGER),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.nat(Number.MAX_SAFE_INTEGER),
        (treeSize, rootHash, timestampMs) => {
          const th = { treeSize, rootHash, timestampMs };
          expect(decodeTreeHead(encodeTreeHead(th))).toEqual(th);
        },
      ),
    );
  });

  it("rejects malformed heads", () => {
    expect(() => encodeTreeHead({ ...head, rootHash: new Uint8Array(31) })).toThrow();
    expect(() => decodeTreeHead(encodeTreeHead(head).subarray(1))).toThrow();
    const bad = encodeTreeHead(head);
    bad[0] = 0;
    expect(() => decodeTreeHead(bad)).toThrow();
  });
});

describe("signed tree heads (ML-DSA-87)", () => {
  it("verify, and any change to size, root, time or signature fails", async () => {
    const sth = await signTreeHead(head, logSign);
    expect(await verifyTreeHead(sth, logVerify)).toBe(true);
    expect(await verifyTreeHead({ ...sth, treeSize: 43 }, logVerify)).toBe(false);
    expect(await verifyTreeHead({ ...sth, timestampMs: sth.timestampMs + 1 }, logVerify)).toBe(false);
    expect(await verifyTreeHead({ ...sth, rootHash: flipBit(sth.rootHash, 3) }, logVerify)).toBe(false);
    expect(await verifyTreeHead({ ...sth, signature: flipBit(sth.signature, 100) }, logVerify)).toBe(false);
    expect(await verifyTreeHead({ ...sth, rootHash: new Uint8Array(5) }, logVerify)).toBe(false);
    // A throwing verifier is a failure, not an exception.
    expect(await verifyTreeHead(sth, () => { throw new Error("boom"); })).toBe(false);
  });

  it("round-trips through JSON", async () => {
    const sth = await signTreeHead(head, logSign);
    const back = sthFromJson(JSON.parse(JSON.stringify(sthToJson(sth))));
    expect(back).toEqual(sth);
    expect(await verifyTreeHead(back, logVerify)).toBe(true);
    expect(() => sthFromJson({ ...sthToJson(sth), treeSize: -1 })).toThrow();
    expect(() => sthFromJson({ ...sthToJson(sth), rootHash: "AAAA" })).toThrow();
    expect(() => sthFromJson({ ...sthToJson(sth), signature: "not base64!" })).toThrow();
    expect(() => sthFromJson(null)).toThrow();
  });
});

describe("cosignatures (ML-DSA-44)", () => {
  it("bind the witness name, cosign time, log and tree head", async () => {
    const logId = await logIdFromPublicKey(logKey.publicKey);
    const otherLog = await logIdFromPublicKey(new Uint8Array(10));
    const c = await cosignTreeHead(head, logId, "krypt-witness-1", 1_760_000_100_000, witSign);
    expect(await verifyCosignature(head, logId, c, witVerify)).toBe(true);
    expect(await verifyCosignature(head, otherLog, c, witVerify)).toBe(false);
    expect(await verifyCosignature({ ...head, treeSize: 41 }, logId, c, witVerify)).toBe(false);
    expect(await verifyCosignature(head, logId, { ...c, witness: "krypt-witness-2" }, witVerify)).toBe(false);
    expect(await verifyCosignature(head, logId, { ...c, timestampMs: c.timestampMs + 1 }, witVerify)).toBe(false);
    expect(await verifyCosignature(head, logId, { ...c, witness: "" }, witVerify)).toBe(false);
  });

  it("message layout is tag || len || name || time || log_id || head", async () => {
    const logId = new Uint8Array(32).fill(0x11);
    const msg = cosignatureMessage("w", 1, logId, head);
    expect(toHex(msg)).toBe(
      toHex(utf8("KRYPT-COSIG-v1\0")) + "01" + "77" + "0000000000000001" + "11".repeat(32) + toHex(encodeTreeHead(head)),
    );
    expect(() => cosignatureMessage("a\nb", 1, logId, head)).toThrow();
    expect(() => cosignatureMessage("x".repeat(256), 1, logId, head)).toThrow();
  });

  it("round-trips through JSON", async () => {
    const logId = await logIdFromPublicKey(logKey.publicKey);
    const c = await cosignTreeHead(head, logId, "w1", 5, witSign);
    expect(cosignatureFromJson(JSON.parse(JSON.stringify(cosignatureToJson(c))))).toEqual(c);
  });
});
