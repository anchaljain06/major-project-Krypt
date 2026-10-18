#!/usr/bin/env node
// Copies ../shared/src/*.ts into src/vendor/krypt-shared/ so the backend can
// import the KT package with its own tsc build (rootDir ./src).
//
//   npm run vendor:shared            refresh the copy
//   npm run vendor:shared -- --check exit 1 if the copy is out of date
//
// Why a committed copy instead of "file:../shared": Render builds from
// primary-backend/ only, so ../shared may not exist at deploy time. The copy
// is committed, and test/vendor.test.ts fails when it drifts from ../shared.
//
// The only rewrite is import specifiers: shared uses "./x.ts" (for Vite and
// Node type stripping); the backend compiles with module=nodenext, which
// wants "./x.js".

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const SHARED_SRC = resolve(HERE, "../../shared/src");
export const VENDOR_DIR = resolve(HERE, "../src/vendor/krypt-shared");

const HEADER =
  "// GENERATED from shared/src by primary-backend/scripts/vendor-shared.mjs. Do not edit;\n" +
  "// change shared/ and run `npm run vendor:shared`.\n";

export function transform(source) {
  return HEADER + source.replace(/(from\s+["']\.\/[^"']+)\.ts(["'])/g, "$1.js$2");
}

/** Expected vendored files: name -> contents. */
export function expectedFiles() {
  const out = new Map();
  for (const name of readdirSync(SHARED_SRC).sort()) {
    if (!name.endsWith(".ts")) continue;
    out.set(name, transform(readFileSync(join(SHARED_SRC, name), "utf8")));
  }
  return out;
}

/** Names of vendored files that are missing, stale or extra. */
export function staleFiles() {
  const want = expectedFiles();
  const bad = [];
  for (const [name, text] of want) {
    const p = join(VENDOR_DIR, name);
    if (!existsSync(p) || readFileSync(p, "utf8") !== text) bad.push(name);
  }
  if (existsSync(VENDOR_DIR)) {
    for (const name of readdirSync(VENDOR_DIR)) if (!want.has(name)) bad.push(name);
  }
  return bad;
}

function main() {
  if (!existsSync(SHARED_SRC)) {
    console.error(`[vendor-shared] ${SHARED_SRC} not found; nothing to do.`);
    process.exit(process.argv.includes("--check") ? 0 : 1);
  }
  if (process.argv.includes("--check")) {
    const bad = staleFiles();
    if (bad.length) {
      console.error(`[vendor-shared] out of date: ${bad.join(", ")}. Run npm run vendor:shared.`);
      process.exit(1);
    }
    console.log("[vendor-shared] up to date.");
    return;
  }
  rmSync(VENDOR_DIR, { recursive: true, force: true });
  mkdirSync(VENDOR_DIR, { recursive: true });
  for (const [name, text] of expectedFiles()) writeFileSync(join(VENDOR_DIR, name), text);
  console.log(`[vendor-shared] wrote ${VENDOR_DIR}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
