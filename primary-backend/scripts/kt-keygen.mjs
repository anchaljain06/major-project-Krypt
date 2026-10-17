#!/usr/bin/env node
// Generates the key transparency log's ML-DSA-87 tree-head signing key.
//
//   npm run kt:keygen
//
// Prints KT_LOG_SK (a 32-byte seed, base64) for the server's environment and
// the public key to pin in the frontend build and the witness
// (KRYPT_LOG_PUBKEY). Nothing is written to disk.

import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
const { publicKey } = ml_dsa87.keygen(seed);
const b64 = (b) => Buffer.from(b).toString("base64");

console.log(`KT_LOG_SK (server secret, keep private):
${b64(seed)}

Log public key (ML-DSA-87, ${publicKey.length} bytes; pin in the frontend build and set as the witness's KRYPT_LOG_PUBKEY):
${b64(publicKey)}`);
