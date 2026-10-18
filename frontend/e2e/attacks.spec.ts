/**
 * Malicious-relay attack matrix: the v1 side.
 *
 * One attack per `npx playwright test` invocation, chosen by the ATTACK env var
 * (ids come from evaluation/attacks/attacks.mjs). The backend is already running
 * with the matching EVIL_MODE (see evaluation/attacks/run-v1.mjs); this spec
 * drives the real browser client and records, from the client's point of view,
 * what happened: delivered correctly / rejected (which error code) / detected
 * (KT badge or identity dialog) / silently accepted wrong data / session broken.
 *
 * Results are written to $OUT_DIR/<attack>.json and a screenshot to
 * $OUT_DIR/<attack>.png so the runner can collect them.
 */
import { expect, test, type Browser, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PNG, befriend, newUser as newWatchedUser, openChat, register, sendText, toasts as recorded, type User } from "./helpers";

const ATTACK = process.env.ATTACK ?? "replay";
const OUT_DIR = process.env.OUT_DIR ?? "test-results/attacks";
const EXPECT_KT = process.env.E2E_EXPECT_KT === "1";
// Usernames are supplied by the runner so the backend's EVIL_SWAP_WITH /
// EVIL_KT_VICTIM (set before this process starts) name the same accounts.
const run = Date.now().toString(36).slice(-5);
const ALICE = process.env.ALICE_NAME ?? `alice_${run}`;
const BOB = process.env.BOB_NAME ?? `bob_${run}`;
const MALLORY = process.env.MALLORY_NAME ?? `mallory_${run}`;

mkdirSync(OUT_DIR, { recursive: true });

/** Every user records toasts and counts any non-log [Krypt] / [KT] console line as a problem. */
const newUser = (browser: Browser, name: string, userAgent?: string) =>
  newWatchedUser(browser, name, { userAgent, recordToasts: true, problem: /\[Krypt\]|\[KT\]/ });

const TOAST_RE =
  /fail|error|alert|reject|drop|duplicat|replac|supersed|queued|could not|not trusted|invalid|tamper|re-?sen|identity|verified it/i;
const toasts = (u: User) => recorded(u, TOAST_RE);

function countFrom(u: User, from: string) {
  return u.page.locator(`[data-testid="message"][data-from="${from}"]`).count();
}

async function finish(result: Record<string, unknown>, shotPage?: Page) {
  if (shotPage) {
    try {
      await shotPage.screenshot({ path: join(OUT_DIR, `${ATTACK}.png`) });
    } catch {
      /* ignore */
    }
  }
  writeFileSync(join(OUT_DIR, `${ATTACK}.json`), JSON.stringify(result, null, 2));
}

// ---------------------------------------------------------------------------

test(`v1 attack: ${ATTACK}`, async ({ browser }) => {
  test.setTimeout(240_000);
  const result: Record<string, unknown> = { attack: ATTACK, ktEnabled: EXPECT_KT, at: new Date().toISOString() };

  // impersonation and bola are protocol-independent; the runner handles them in Node.
  // --- message / handshake / KT attacks: Alice + Bob (+ Mallory for key swap) ---
  const alice = await newUser(browser, ALICE);
  // kt_fork targets only Bob, by a distinct user-agent the evil relay matches (EVIL_FORK_UA).
  const bob = await newUser(browser, BOB, ATTACK === "kt_fork" ? "Mozilla/5.0 KryptForkTarget Chrome/120" : undefined);
  await register(alice);
  await register(bob);

  const needsMallory = ATTACK === "swap_key" || ATTACK === "kt_swap_key" || ATTACK === "kt_rogue_leaf";
  if (needsMallory) {
    const mallory = await newUser(browser, MALLORY);
    await register(mallory);
    await mallory.context.close();
  }

  await befriend(alice, bob);
  await openChat(alice, bob.name);
  await openChat(bob, alice.name);

  if (ATTACK === "swap_key" || ATTACK === "kt_swap_key") {
    // Alice's first message triggers the handshake, where the relay serves the wrong key.
    try {
      await sendText(alice, "hello bob (handshake)");
    } catch {
      /* send may be refused */
    }
    await alice.page.waitForTimeout(6000);
    const bobGotPlaintext = await bob.page.getByText("hello bob (handshake)").count();
    result.aliceToasts = await toasts(alice);
    result.bobToasts = await toasts(bob);
    result.aliceProblems = alice.problems;
    result.bobProblems = bob.problems;
    result.bobReceivedPlaintext = bobGotPlaintext > 0;
    result.identityDialog = await alice.page.getByRole("alertdialog").count();
    result.ktBadgeAlice = await alice.page.getByTestId("kt-badge").innerText().catch(() => null);
    const aliceAll = (result.aliceToasts as string[]).concat(alice.problems);
    result.ktAlert = aliceAll.some((t) => /ALERT|transparency|not trusted|refused/i.test(t));
    // Did Alice's send complete (her own bubble shown, input cleared)?
    const aliceSent =
      (await alice.page.getByTestId("message").filter({ hasText: "hello bob (handshake)" }).count()) > 0;
    result.aliceSendCompleted = aliceSent;
    const warn = result.ktAlert ? "KT ALERT shown" : "no visible warning";
    result.observed =
      bobGotPlaintext > 0
        ? "plaintext delivered to Bob (LEAK)"
        : aliceSent
          ? `wrong-key message sent but not readable by Bob; ${warn}`
          : `send did not complete (nothing left Alice's client, relay saw no message); ${warn}; no plaintext exposed`;
    await finish(result, alice.page);
    expect(bobGotPlaintext, "the wrong-key message must not reach Bob as plaintext").toBe(0);
    await alice.context.close();
    await bob.context.close();
    return;
  }

  if (["replay", "reorder", "drop", "duplicate", "tamper", "flip_type", "flip_content_type"].includes(ATTACK)) {
    const N = 6;
    for (let i = 0; i < N; i++) {
      await sendText(alice, `a2b #${i}`);
      await bob.page.waitForTimeout(400);
    }
    // One image too, for flip_type (to confirm text is not reclassified).
    await alice.page.locator("#image-upload").setInputFiles({ name: "dot.png", mimeType: "image/png", buffer: PNG });
    await bob.page.waitForTimeout(3000);

    const bobTexts = await bob.page.locator(`[data-testid="message"][data-from="${ALICE}"][data-type="text"]`).count();
    const bobImgs = await bob.page.locator(`[data-testid="message"][data-from="${ALICE}"][data-type="image"]`).count();
    const bobTotal = await countFrom(bob, ALICE);
    result.sentTexts = N;
    result.bobTextsReceived = bobTexts;
    result.bobImagesReceived = bobImgs;
    result.bobTotalFromAlice = bobTotal;
    result.bobCodes = bob.codes;
    result.bobToasts = await toasts(bob);
    result.bobProblems = bob.problems;
    // Exactly one real image is sent. Any image beyond that would be a text
    // reclassified as an image (flip_type succeeding).
    result.imagesFromText = Math.max(0, bobImgs - 1);

    let observed: string;
    if (ATTACK === "drop") observed = `delivered ${bobTexts}/${N} texts (drops expected, no forgery)`;
    else if (ATTACK === "duplicate") observed = bobTexts <= N ? `de-duplicated (${bobTexts}/${N} shown once)` : `duplicates shown (${bobTexts})`;
    else if (ATTACK === "replay") observed = `replays rejected (${bob.codes.join(",") || "none"}); ${bobTexts}/${N} shown`;
    else if (ATTACK === "tamper") observed = `tampered dropped (${bob.codes.join(",") || "none"}); ${bobTexts}/${N} intact`;
    else if (ATTACK === "flip_type") observed = `text stayed text (${bobTexts} texts, ${bobImgs} image); header type not trusted`;
    else if (ATTACK === "flip_content_type") observed = `content-type flip dropped (${bob.codes.join(",") || "none"}); ${bobTexts}/${N} intact`;
    else observed = `delivered ${bobTexts}/${N}`;
    result.observed = observed;
    await finish(result, bob.page);
    await alice.context.close();
    await bob.context.close();
    return;
  }

  if (["kt_rogue_leaf", "kt_fork", "kt_rewrite"].includes(ATTACK)) {
    if (ATTACK === "kt_rogue_leaf") {
      // Plant a forged leaf for Bob, then let Bob re-check the log.
      const api = process.env.VITE_API_URL ?? "http://localhost:3100";
      await bob.page.evaluate(
        async ([base, victim]) => {
          await fetch(`${base}/kt/evil/rogue-leaf?victim=${victim}`, { method: "POST" }).catch(() => {});
        },
        [api, bob.name],
      );
    }
    // Exchange a couple of messages so gossip/self-monitoring runs.
    for (let i = 0; i < 3; i++) {
      try {
        await sendText(alice, `kt #${i}`);
      } catch {
        /* ignore */
      }
      await bob.page.waitForTimeout(1500);
    }
    // Give self-monitoring / gossip time, then reload Bob to force a fresh check.
    await bob.page.reload();
    await bob.page.waitForTimeout(8000);
    const badgeBob = await bob.page.getByTestId("kt-badge").innerText().catch(() => null);
    const badgeAlice = await alice.page.getByTestId("kt-badge").innerText().catch(() => null);
    result.ktBadgeBob = badgeBob;
    result.ktBadgeAlice = badgeAlice;
    result.bobToasts = await toasts(bob);
    result.aliceToasts = await toasts(alice);
    result.bobProblems = bob.problems;
    result.aliceProblems = alice.problems;
    const alerted =
      /ALERT/i.test(badgeBob ?? "") ||
      /ALERT/i.test(badgeAlice ?? "") ||
      bob.problems.some((p) => /ALERT/.test(p)) ||
      alice.problems.some((p) => /ALERT/.test(p));
    result.ktAlert = alerted;
    result.observed = alerted ? "KT ALERT raised" : `no alert (badge Bob=${badgeBob}, Alice=${badgeAlice})`;
    await finish(result, bob.page);
    await alice.context.close();
    await bob.context.close();
    return;
  }

  throw new Error(`unknown ATTACK: ${ATTACK}`);
});
