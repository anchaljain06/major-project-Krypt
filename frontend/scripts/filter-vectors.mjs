// Trims the raw KAT downloads (scripts/fetch-vectors.sh) down to the groups our
// wrappers implement and writes flat JSON files to test/vectors/.
//
//   node scripts/filter-vectors.mjs [rawDir] [outDir]
//
// Kept: ML-KEM-1024 only (the one KEM Krypt uses), ML-DSA-87 "external/pure" only (Krypt never
// uses HashML-DSA or the internal interface), AES-GCM with 256-bit keys,
// 96-bit IVs and 128-bit tags (the only shape aes_gcm in kdf.ts accepts).
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const raw = process.argv[2] || join(here, "../test/vectors/raw"); // "" (unset RAW) = default
const out = process.argv[3] || join(here, "../test/vectors");
mkdirSync(out, { recursive: true });

const read = (p) => JSON.parse(readFileSync(join(raw, p), "utf8"));
const write = (name, data) => {
  writeFileSync(join(out, name), JSON.stringify(data) + "\n");
  console.log(`wrote ${name}`);
};

// --- NIST ACVP ML-KEM encapDecap (FIPS 203) --------------------------------
{
  const prompt = read("acvp/ML-KEM-encapDecap-FIPS203-prompt.json");
  const expected = read("acvp/ML-KEM-encapDecap-FIPS203-expectedResults.json");
  const results = new Map(expected.testGroups.map((g) => [g.tgId, new Map(g.tests.map((t) => [t.tcId, t]))]));
  const groups = prompt.testGroups
    .filter((g) => g.parameterSet === "ML-KEM-1024")
    .map((g) => ({
      tgId: g.tgId,
      parameterSet: g.parameterSet,
      function: g.function,
      tests: g.tests.map((t) => ({ ...t, ...results.get(g.tgId).get(t.tcId) })),
    }));
  write("acvp-mlkem-encapdecap.json", { source: "usnistgov/ACVP-Server ML-KEM-encapDecap-FIPS203", vsId: prompt.vsId, groups });
}

// --- NIST ACVP ML-DSA sigVer (FIPS 204) -------------------------------------
{
  const prompt = read("acvp/ML-DSA-sigVer-FIPS204-prompt.json");
  const expected = read("acvp/ML-DSA-sigVer-FIPS204-expectedResults.json");
  const results = new Map(expected.testGroups.map((g) => [g.tgId, new Map(g.tests.map((t) => [t.tcId, t]))]));
  const groups = prompt.testGroups
    .filter((g) => g.parameterSet === "ML-DSA-87" && g.signatureInterface === "external" && g.preHash === "pure")
    .map((g) => ({
      tgId: g.tgId,
      parameterSet: g.parameterSet,
      tests: g.tests.map((t) => ({ ...t, ...results.get(g.tgId).get(t.tcId) })),
    }));
  write("acvp-mldsa87-sigver.json", { source: "usnistgov/ACVP-Server ML-DSA-sigVer-FIPS204", vsId: prompt.vsId, groups });
}

// --- Wycheproof --------------------------------------------------------------
const flatten = (file, keep = () => true, extra = () => ({})) => {
  const d = read(`wycheproof/${file}`);
  const tests = [];
  for (const g of d.testGroups) {
    if (!keep(g)) continue;
    for (const t of g.tests) tests.push({ ...extra(g), ...t });
  }
  return { source: `C2SP/wycheproof testvectors_v1/${file}`, tests };
};

write("wycheproof-hkdf-sha256.json", flatten("hkdf_sha256_test.json"));
write("wycheproof-hmac-sha256.json", flatten("hmac_sha256_test.json", () => true, (g) => ({ tagSize: g.tagSize })));
write(
  "wycheproof-aes-gcm-256.json",
  flatten("aes_gcm_test.json", (g) => g.keySize === 256 && g.ivSize === 96 && g.tagSize === 128),
);
{
  const p = "1024";
  write(`wycheproof-mlkem-${p}.json`, flatten(`mlkem_${p}_test.json`, () => true, (g) => ({ parameterSet: g.parameterSet })));
  write(
    `wycheproof-mlkem-${p}-encaps.json`,
    flatten(`mlkem_${p}_encaps_test.json`, () => true, (g) => ({ parameterSet: g.parameterSet })),
  );
}
if (existsSync(join(raw, "wycheproof/mldsa_87_verify_test.json"))) {
  // Grouped (not flattened) because each group shares one 2.6 KB public key.
  const d = read("wycheproof/mldsa_87_verify_test.json");
  write("wycheproof-mldsa87-verify.json", {
    source: "C2SP/wycheproof testvectors_v1/mldsa_87_verify_test.json",
    groups: d.testGroups.map((g) => ({ publicKey: g.publicKey, tests: g.tests })),
  });
}
