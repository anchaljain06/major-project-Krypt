/**
 * Safety numbers and key fingerprints (plan 3.4).
 *
 *   h      = SHA-256(min(IK_A, IK_B) ‖ max(IK_A, IK_B))      // ML-DSA-87 public keys, bytewise order
 *   stream = h ‖ SHA-256(h)                                  // 64 bytes
 *   group i (0..11) = uint40be(stream[5i .. 5i+5]) mod 100000, as 5 digits
 *
 * Both keys have the fixed length 2592, so the concatenation is unambiguous,
 * and sorting makes the number identical on both sides. The second hash only
 * stretches the 32-byte digest to the 60 bytes that 12 groups need; the
 * security of the comparison is that of h.
 */
import { compareBytes, concat } from "./encoding";
import { sha256 } from "./kdf";

export const SAFETY_GROUPS = 12;

export async function safetyNumber(ikA: Uint8Array, ikB: Uint8Array): Promise<string[]> {
  if (ikA.length === 0 || ikB.length === 0) throw new Error("both identity keys are required");
  const [lo, hi] = compareBytes(ikA, ikB) <= 0 ? [ikA, ikB] : [ikB, ikA];
  const h = await sha256(concat(lo, hi));
  const stream = concat(h, await sha256(h));
  const groups: string[] = [];
  for (let i = 0; i < SAFETY_GROUPS; i++) {
    let v = 0;
    for (let j = 0; j < 5; j++) v = v * 256 + stream[5 * i + j]!;
    groups.push(String(v % 100000).padStart(5, "0"));
  }
  return groups;
}

/** Short fingerprint of one key for warnings: first 16 bytes of SHA-256, hex in groups of 4. */
export async function keyFingerprint(key: Uint8Array): Promise<string> {
  const h = await sha256(key);
  const hex = Array.from(h.subarray(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g)!.join(" ");
}
