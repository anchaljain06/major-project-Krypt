#!/usr/bin/env bash
# Downloads the raw KAT sources (NIST ACVP + Wycheproof) into the directory
# given as $1 (default: test/vectors/raw, which is gitignored).
# The committed, trimmed copies in test/vectors/ are produced from these by
# scripts/filter-vectors.mjs. Run both to refresh the vectors:
#   bash scripts/fetch-vectors.sh && node scripts/filter-vectors.mjs
set -euo pipefail
OUT="${1:-$(dirname "$0")/../test/vectors/raw}"
mkdir -p "$OUT/acvp" "$OUT/wycheproof"

ACVP=https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files
for d in ML-KEM-encapDecap-FIPS203 ML-DSA-sigVer-FIPS204; do
  for f in prompt.json expectedResults.json; do
    curl -sSfL -o "$OUT/acvp/$d-$f" "$ACVP/$d/$f"
  done
done

WY=https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1
for f in hkdf_sha256_test.json hmac_sha256_test.json aes_gcm_test.json \
         mlkem_1024_test.json mlkem_1024_encaps_test.json \
         mldsa_87_verify_test.json; do
  curl -sSfL -o "$OUT/wycheproof/$f" "$WY/$f"
done
echo "downloaded into $OUT"
