#!/usr/bin/env node
// Regenerates test/vectors/tdm-{inclusion,consistency}.json from a checkout of
// https://github.com/transparency-dev/merkle (Apache-2.0).
//
//   git clone --depth 1 https://github.com/transparency-dev/merkle /tmp/tdm
//   node scripts/import-tdm-vectors.mjs /tmp/tdm
//
// The upstream probes are ~200 small JSON files; we bundle them into two files
// and keep each probe's relative path so a failure points back upstream.
// Integers above 2^53 (e.g. leafIdx = 2^64 - 1) are kept as decimal strings,
// because JSON.parse would silently round them.

import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const src = process.argv[2];
if (!src) {
  console.error("usage: node scripts/import-tdm-vectors.mjs <path-to-transparency-dev/merkle>");
  process.exit(2);
}

const commit = execFileSync("git", ["-C", src, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();

function walk(dir) {
  return readdirSync(dir)
    .sort()
    .flatMap((name) => {
      const p = join(dir, name);
      return statSync(p).isDirectory() ? walk(p) : p.endsWith(".json") ? [p] : [];
    });
}

function parseKeepingBigInts(text) {
  // Quote any bare integer literal of 16+ digits before parsing.
  return JSON.parse(text.replace(/(:\s*)(\d{16,})(\s*[,}\n])/g, '$1"$2"$3'));
}

for (const kind of ["inclusion", "consistency"]) {
  const dir = join(src, "testdata", kind);
  const probes = walk(dir).map((file) => ({
    file: relative(join(src, "testdata"), file),
    ...parseKeepingBigInts(readFileSync(file, "utf8")),
  }));
  const out = {
    source: "https://github.com/transparency-dev/merkle/tree/main/testdata/" + kind,
    commit,
    license: "Apache-2.0, Copyright Google LLC. Probe data copied unmodified apart from bundling.",
    probes,
  };
  const dest = new URL(`../test/vectors/tdm-${kind}.json`, import.meta.url);
  writeFileSync(dest, JSON.stringify(out, null, 1) + "\n");
  console.log(`${kind}: ${probes.length} probes -> ${dest.pathname}`);
}
