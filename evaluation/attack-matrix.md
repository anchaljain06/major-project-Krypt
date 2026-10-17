# Attack matrix: v0 vs v1 under a malicious relay

Run on 2026-10-17 with two real browser clients (Playwright, Chromium) against a relay in `EVIL_MODE` (`primary-backend/src/evil.ts`). v0 is tag `protocol-v0`, attacked through a malicious proxy. Raw results and screenshots are in `results/attack-matrix-2026-10-17/`.

**Status: partial.** Every v1 attack ran. The v0 run was stopped early by choice, so only the attacks marked below ran against v0.

| Attack | What the relay does | v0 observed | v1 observed |
|---|---|---|---|
| Impersonation | Opens a socket claiming to be Bob, with no credentials | **Succeeded**: impostor received Bob's queued message (mailbox drained) | Refused: `connect_error: unauthorized` |
| BOLA | Calls `POST /api/request/accept` on Bob's behalf, no token | **Succeeded**: HTTP 200, attacker added to Bob's friends | Refused: HTTP 401 |
| Flip type (outer field) | Sets the payload `type` to `image` | **Succeeded**: text rendered as `<img>`; Bob's browser fetched the attacker's URL (tracking pixel) | Ignored: the header type is not trusted, text stayed text |
| Flip content type (authenticated field) | Changes `contentType` inside the v1 envelope | n/a (no such field in v0) | Rejected: `AUTH_FAILED` on every message, 0/6 accepted |
| Replay | Re-sends earlier messages | **No protection**: replays accepted (5/6 delivered) | Rejected as `DUPLICATE`; each message shown once (6/6) |
| Duplicate | Delivers each message twice | not run | De-duplicated; each shown once (6/6) |
| Reorder | Holds a message and releases it after the next | not run (spec failed) | Delivered 6/6 |
| Drop | Drops every 3rd message | not run | 4/6 delivered, no forgery. v1 does not claim delivery guarantees |
| Tamper | Flips one bit in a random field | not run | Rejected: `BAD_SIGNATURE` / `AUTH_FAILED`, 0/6 accepted |
| Key swap, KT off | Serves Mallory's keys as Bob's | not run | Send blocked, no plaintext exposed, **but no visible warning**. Trust on first use cannot spot a first-contact swap; this is the gap key transparency closes |
| Key swap, KT on | Same, with key transparency enabled | n/a | Send blocked, no plaintext exposed, **but no visible warning yet**. UX gap: the client should show why |
| KT rogue leaf | Appends a fake key for Bob to the log | n/a | **KT ALERT** raised |
| KT fork | Shows one client a different log | n/a | **KT ALERT** raised |
| KT rewrite | Rewrites an old log entry | n/a | **KT ALERT** raised |

## What is left

1. Run the remaining v0 attacks: duplicate, reorder, drop, tamper, key swap. Specs: `frontend/e2e/attacks.spec.ts`, `frontend/e2e/attacks-v0.spec.ts`. Runners and the v0 malicious proxy: `evaluation/attacks/` (`run-v1.mjs`, `run-v0.mjs`, `evil-proxy.mjs`).
2. Show a visible warning when a key-swap blocks a send (both KT on and off).
3. Repeat the runs in Firefox and WebKit.
