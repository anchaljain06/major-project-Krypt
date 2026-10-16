import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dir = join(import.meta.dirname, "..", "vectors");

/** Path of a vector file, or null if it was not fetched (large files are gitignored). */
export function vectorPath(name: string): string | null {
  const p = join(dir, name);
  return existsSync(p) ? p : null;
}

export function loadVectors<T>(name: string): T {
  const p = vectorPath(name);
  if (!p) throw new Error(`missing test/vectors/${name}; run: npm run vectors:fetch`);
  return JSON.parse(readFileSync(p, "utf8")) as T;
}

export const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
export const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
