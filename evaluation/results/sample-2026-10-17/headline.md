# Headline numbers: results/sample-2026-10-17

### ML-KEM-768 (median of run medians)

| source | op | noble | liboqs-wasm | webcrypto-native | node-crypto |
|---|---|---:|---:|---:|---:|
| chromium | keygen | 182.6 µs | 18.9 µs | 13.3 µs | – |
| chromium | encaps | 210.7 µs | 18.7 µs | 5.8 µs | – |
| chromium | decaps | 174.9 µs | 22.8 µs | 8.6 µs | – |
| firefox | keygen | 265.4 µs | 21.3 µs | unsupported | – |
| firefox | encaps | 297.1 µs | 22.5 µs | unsupported | – |
| firefox | decaps | 268.7 µs | 26.2 µs | unsupported | – |
| node | keygen | 196.5 µs | 19.1 µs | 35.7 µs | 24.1 µs |
| node | encaps | 252.0 µs | 19.4 µs | 23.8 µs | 16.4 µs |
| node | decaps | 209.5 µs | 22.3 µs | 32.0 µs | 24.1 µs |
| webkit | keygen | 331.1 µs | 21.5 µs | unsupported | – |
| webkit | encaps | 413.8 µs | 22.0 µs | unsupported | – |
| webkit | decaps | 417.0 µs | 25.9 µs | unsupported | – |

### ML-DSA-65 (median of run medians)

| source | op | noble | liboqs-wasm | webcrypto-native | node-crypto |
|---|---|---:|---:|---:|---:|
| chromium | keygen | 710.8 µs | 62.9 µs | 53.0 µs | – |
| chromium | sign | 2.95 ms | 188.3 µs | 163.3 µs | – |
| chromium | verify | 773.7 µs | 52.9 µs | 42.5 µs | – |
| firefox | keygen | 775.3 µs | 71.0 µs | unsupported | – |
| firefox | sign | 2.96 ms | 205.4 µs | unsupported | – |
| firefox | verify | 800.7 µs | 60.2 µs | unsupported | – |
| node | keygen | 1.27 ms | 63.0 µs | 98.6 µs | 82.0 µs |
| node | sign | 8.52 ms | 202.7 µs | 401.0 µs | 389.9 µs |
| node | verify | 1.50 ms | 52.1 µs | 83.9 µs | 72.0 µs |
| webkit | keygen | 1.24 ms | 71.5 µs | unsupported | – |
| webkit | sign | 11.37 ms | 197.3 µs | unsupported | – |
| webkit | verify | 1.61 ms | 60.2 µs | unsupported | – |
