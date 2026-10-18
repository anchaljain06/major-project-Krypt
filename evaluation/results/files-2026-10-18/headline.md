# Phase E file benchmarks (2026-10-18)

Chromium 156.0.8078.4, production build, local relay and Postgres on one machine (Apple M5, Battery Power, 61%). Median over fresh user pairs (range in brackets).

## Chunk size (100 MiB file, 5 runs each)

| Chunk | Accept to done, ms | MiB/s | Retries | Peak heap growth, MiB (sender / receiver) | Peak buffer growth, MiB (sender / receiver) | Long tasks (sender / receiver) | Longest task, ms | Bytes match |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 256 KiB | 1310 (1290-1338) | 76.3 | 0 | 2.5 / 2.7 | 18.9 / 12.9 | 0 / 0 | 0 | yes |
| 1024 KiB | 1326 (1291-1421) | 75.4 | 0 | 1.6 / 1.6 | 39.2 / 21.3 | 0 / 0 | 0 | yes |
| 4096 KiB | 1313 (1297-1347) | 76.2 | 0 | 1.1 / 1.0 | 44.1 / 44.3 | 0 / 0 | 0 | yes |

## Resume (64 MiB, 1 MiB chunks, receiver offline 2000 ms after half the chunks)

| Completed, bytes match | Sender paused | Reconnect to done, ms | Chunks re-sent | Re-sent bytes | One nonce counter per chunk | Re-sends byte-identical | Counter reused |
|---:|---:|---:|---:|---:|---|---|---|
| 5/5 | 0/5 | 2794 (1994-3507) | 8 (8-8) | 8.0 MiB | yes | yes | no |

## Entire experience (3 runs; file 10 MiB)

| Phase | Time, ms | Up, KiB (WS + HTTP) | Down, KiB (WS + HTTP) |
|---|---:|---:|---:|
| register | 1006 | 1668 | 17 |
| befriend | 1061 | 2 | 8 |
| firstMessage | 54 | 13 | 41 |
| messages100 | 2830 | 291 | 298 |
| file | 1643 | 10265 | 10266 |
| total | 6635 | 12240 | 10629 |
