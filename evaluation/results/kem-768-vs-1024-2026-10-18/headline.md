# Headline numbers: results/kem-768-vs-1024-2026-10-18

### ML-KEM-768 (median of run medians)

| source | op | noble | liboqs-wasm | webcrypto-native | node-crypto |
|---|---|---:|---:|---:|---:|
| chromium | keygen | 170.9 µs | – | – | – |
| chromium | encaps | 206.0 µs | – | – | – |
| chromium | decaps | 173.6 µs | – | – | – |
| node | keygen | 188.3 µs | – | – | – |
| node | encaps | 238.3 µs | – | – | – |
| node | decaps | 195.8 µs | – | – | – |

### ML-DSA-65 (median of run medians)

| source | op | noble | liboqs-wasm | webcrypto-native | node-crypto |
|---|---|---:|---:|---:|---:|
| chromium | keygen | – | – | – | – |
| chromium | sign | – | – | – | – |
| chromium | verify | – | – | – | – |
| node | keygen | – | – | – | – |
| node | sign | – | – | – | – |
| node | verify | – | – | – | – |
