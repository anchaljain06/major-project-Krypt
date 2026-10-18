/**
 * Aggregate the per-attack result JSON (written by run-v0.mjs / run-v1.mjs) into:
 *   evaluation/attack-matrix-v0.json   array of raw v0 results
 *   evaluation/attack-matrix-v1.json   array of raw v1 results
 *   evaluation/attack-matrix.md        the single comparison table
 *
 * Usage: node evaluation/attacks/build-matrix.mjs <resultsDir>
 *   resultsDir holds v0/ and v1/ subdirectories of <attack>.json files.
 */
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { ATTACKS } from "./attacks.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const EVAL = join(ROOT, "evaluation");
const resultsDir = process.argv[2] ?? join(EVAL, "results", "attack-matrix-dev");

function load(dir) {
  const out = {};
  if (!existsSync(dir)) return out;
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".json"))) {
    try {
      out[basename(f, ".json")] = JSON.parse(readFileSync(join(dir, f), "utf8"));
    } catch {
      /* ignore */
    }
  }
  return out;
}

const v0 = load(join(resultsDir, "v0"));
const v1 = load(join(resultsDir, "v1"));

writeFileSync(join(EVAL, "attack-matrix-v0.json"), JSON.stringify(Object.values(v0), null, 2) + "\n");
writeFileSync(join(EVAL, "attack-matrix-v1.json"), JSON.stringify(Object.values(v1), null, 2) + "\n");

const shotRel = (flavor, id) => {
  const p = join(resultsDir, flavor, `${id}.png`);
  return existsSync(p) ? relative(EVAL, p) : "";
};
const cell = (v) => (v === undefined || v === null || v === "" ? "—" : String(v).replace(/\|/g, "\\|"));

const rows = ATTACKS.map((a) => {
  const r0 = v0[a.id];
  const r1 = v1[a.id];
  const v0obs = a.kt ? "n/a (no KT in v0)" : r0?.observed ?? "not run";
  const v1obs = r1?.observed ?? "not run";
  const ev = [
    r1 ? (a.id === "impersonation" || a.id === "bola" ? "node check" : `attacks.spec.ts :: ${a.id}`) : "",
    shotRel("v1", a.id),
    shotRel("v0", a.id),
  ]
    .filter(Boolean)
    .join("<br>");
  return `| ${a.id} | ${cell(a.relay)} | ${cell(a.expected)} | ${cell(v0obs)} | ${cell(v1obs)} | ${cell(ev)} |`;
});

const md = `# Attack matrix: Krypt v0 vs v1

Malicious-relay attacks run against the old app (tag \`protocol-v0\`) and the new
app (this branch) with two real browser clients. "What the relay does" is the
transform the evil relay applies; "v0/v1 observed" is what the two browser
clients actually did. Generated ${new Date().toISOString().slice(0, 10)} from
${relative(ROOT, resultsDir)}.

v0 has no evil mode, so the same transforms are applied by a socket.io **evil
proxy** (\`evaluation/attacks/evil-proxy.mjs\`) placed in front of the untouched
v0 server; it reuses the v1 backend's transform code (\`primary-backend/src/evil.ts\`,
compiled). v1 uses the backend's built-in \`EVIL_MODE\`.

| attack | what the relay does | expected secure behaviour | v0 observed | v1 observed | evidence |
|---|---|---|---|---|---|
${rows.join("\n")}

## How to rerun

Prereqs: Docker, Node, a checkout of this repo, and the \`protocol-v0\` tag.

\`\`\`bash
# 1. Throwaway Postgres
docker run -d --name krypt-pg-matrix -e POSTGRES_PASSWORD=pg -p 55434:5432 postgres:16
export DATABASE_URL=postgresql://postgres:pg@localhost:55434/postgres
export DIRECT_URL=$DATABASE_URL

# 2. v1 backend: install, migrate, build; frontend: install + chromium
(cd primary-backend && npm ci && npx prisma migrate deploy && npx tsc)
(cd frontend && npm ci && npx playwright install chromium)

# 3. v0 copy OUTSIDE the repo (its deps, its DB)
SCRATCH=$(mktemp -d)
git archive protocol-v0 | tar -x -C "$SCRATCH"
(cd "$SCRATCH/primary-backend" && npm ci \\
   && DATABASE_URL=postgresql://postgres:pg@localhost:55434/krypt_v0 \\
      DIRECT_URL=postgresql://postgres:pg@localhost:55434/krypt_v0 npx prisma db push \\
   && npx tsc)
(cd "$SCRATCH/frontend" && npm ci)

# 4. Run the matrix (dates the output dir)
OUT=evaluation/results/attack-matrix-$(date +%F)
node evaluation/attacks/run-v1.mjs           # all v1 attacks -> $OUT/v1  (pass OUT_DIR)
V0_DIR="$SCRATCH" \\
  DATABASE_URL=postgresql://postgres:pg@localhost:55434/krypt_v0 \\
  DIRECT_URL=postgresql://postgres:pg@localhost:55434/krypt_v0 \\
  node evaluation/attacks/run-v0.mjs          # v0 attacks -> $OUT/v0
node evaluation/attacks/build-matrix.mjs "$OUT"

# 5. Clean up
docker rm -f krypt-pg-matrix
\`\`\`

Set \`OUT_DIR=$OUT/v1\` (v1) and \`OUT_DIR=$OUT/v0\` (v0) to land results under the
dated directory. Run a single attack by passing its id, e.g.
\`node evaluation/attacks/run-v1.mjs tamper\`.
`;

writeFileSync(join(EVAL, "attack-matrix.md"), md);
console.log(`Wrote attack-matrix.md, attack-matrix-v0.json (${Object.keys(v0).length}), attack-matrix-v1.json (${Object.keys(v1).length})`);
