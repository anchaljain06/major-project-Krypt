#!/usr/bin/env node
// Generates a witness ML-DSA-44 key pair.
//
//   node scripts/keygen.mjs
//
// Prints the secret (a 32-byte seed, base64) for the WITNESS_SK GitHub secret
// and the public key that Krypt clients pin. Nothing is written to disk: the
// seed must only ever live in GitHub Secrets (and an offline backup if you
// want the witness to survive a lost secret).

import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { toBase64 } from "../lib/krypt-shared/index.js";

const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
const { publicKey } = ml_dsa44.keygen(seed);

console.log(`WITNESS_SK (GitHub secret, keep private):
${toBase64(seed)}

Witness public key (ML-DSA-44, ${publicKey.length} bytes, pin this in the Krypt frontend build):
${toBase64(publicKey)}`);
