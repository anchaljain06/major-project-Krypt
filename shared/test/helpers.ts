import { fromBase64, fromHex } from "../src/bytes.ts";

export const hx = fromHex;

/** Decodes a base64 field from the upstream probes; malformed input becomes a wrong-length hash. */
export function b64(s: string | null | undefined): Uint8Array {
  if (s === null || s === undefined || s === "") return new Uint8Array(0);
  return fromBase64(s);
}

/**
 * Upstream integers are uint64. Values above 2^53 were stored as strings; we
 * pass them through as an unsafe number, which the API must reject.
 */
export function u64(v: number | string): number {
  return typeof v === "string" ? Number(BigInt(v)) : v;
}

/** The 8 leaf inputs from transparency-dev/merkle testonly/constants.go (RFC 6962 reference tree). */
export const TDM_LEAF_INPUTS: Uint8Array[] = [
  "",
  "00",
  "10",
  "2021",
  "3031",
  "40414243",
  "5051525354555657",
  "606162636465666768696a6b6c6d6e6f",
].map(fromHex);

/** Leaf i of the synthetic trees used by structural and property tests. */
export function syntheticLeaf(i: number): Uint8Array {
  return new TextEncoder().encode(`leaf-${i}`);
}

/** Copy of h with one bit flipped. */
export function flipBit(h: Uint8Array, bit: number): Uint8Array {
  const out = new Uint8Array(h);
  out[Math.floor(bit / 8) % out.length]! ^= 1 << (bit % 8);
  return out;
}
