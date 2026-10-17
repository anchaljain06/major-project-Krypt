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
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ATTACK = process.env.ATTACK ?? "replay";
const OUT_DIR = process.env.OUT_DIR ?? "test-results/attacks";
const EXPECT_KT = process.env.E2E_EXPECT_KT === "1";
// Usernames are supplied by the runner so the backend's EVIL_SWAP_WITH /
// EVIL_KT_VICTIM (set before this process starts) name the same accounts.
const run = Date.now().toString(36).slice(-5);
const ALICE = process.env.ALICE_NAME ?? `alice_${run}`;
const BOB = process.env.BOB_NAME ?? `bob_${run}`;
const MALLORY = process.env.MALLORY_NAME ?? `mallory_${run}`;
const PASSWORD = "correct horse battery staple";
const VAULT_PASSWORD = "vault-password-123";

mkdirSync(OUT_DIR, { recursive: true });

const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==",
  "base64",
);

const DECRYPT_CODE = /\[Krypt\] decrypt from \S+ failed:\s*([A-Z_]+)/;

interface User {
  name: string;
  context: BrowserContext;
  page: Page;
  problems: string[];
  codes: string[];
}

function watch(u: User) {
  u.page.on("console", (msg) => {
    const t = msg.text();
    const m = DECRYPT_CODE.exec(t);
    if (m) u.codes.push(m[1]!);
    if (/\[Krypt\]|\[KT\]/.test(t) && msg.type() !== "log") u.problems.push(`${msg.type()}: ${t}`);
  });
  u.page.on("pageerror", (err) => u.problems.push(`pageerror: ${err.message}`));
}

async function newUser(browser: Browser, name: string, userAgent?: string): Promise<User> {
  const context = await browser.newContext({ acceptDownloads: true, ...(userAgent ? { userAgent } : {}) });
  const page = await context.newPage();
  // Record toast text as it appears (toasts auto-dismiss, so capture live).
  await page.addInitScript(() => {
    (window as unknown as { __toasts: string[] }).__toasts = [];
    const push = (el: Element) => {
      const t = (el.textContent ?? "").trim();
      // Toasts are short; skip large app-container blobs.
      if (t && t.length <= 160) (window as unknown as { __toasts: string[] }).__toasts.push(t);
    };
    const start = () => {
      const obs = new MutationObserver((muts) => {
        for (const mu of muts)
          mu.addedNodes.forEach((n) => {
            if (n.nodeType === 1) push(n as Element);
          });
      });
      obs.observe(document.body, { childList: true, subtree: true });
    };
    if (document.body) start();
    else window.addEventListener("DOMContentLoaded", start);
  });
  const u: User = { name, context, page, problems: [], codes: [] };
  watch(u);
  return u;
}

const TOAST_RE =
  /fail|error|alert|reject|drop|duplicat|replac|supersed|queued|could not|not trusted|invalid|tamper|re-?sen|identity|verified it/i;
async function toasts(u: User): Promise<string[]> {
  const raw = await u.page.evaluate(() => (window as unknown as { __toasts?: string[] }).__toasts ?? []);
  return Array.from(new Set(raw.filter((t) => TOAST_RE.test(t))));
}

async function register(u: User) {
  const { page } = u;
  await page.goto("/");
  await page.getByRole("button", { name: "New here? Establish identity." }).click();
  await page.getByPlaceholder("Enter your alias").fill(u.name);
  await page.getByPlaceholder("Enter your secure password").fill(PASSWORD);
  await page.getByRole("button", { name: "Generate Proofs & Register" }).click();
  await page.getByPlaceholder(/Vault password \(min/).fill(VAULT_PASSWORD);
  await page.getByPlaceholder("Confirm vault password").fill(VAULT_PASSWORD);
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download Encrypted Vault" }).click();
  await download;
  await page.getByRole("button", { name: "I saved it, continue" }).click();
  await expect(page.getByTestId("kt-badge")).toBeVisible();
}

async function befriend(a: User, b: User) {
  await a.page.getByRole("button", { name: /^Requests/ }).click();
  await a.page.getByPlaceholder("Search global network...").fill(b.name);
  await a.page.getByRole("button", { name: "Invite" }).click();
  await b.page.getByRole("button", { name: /^Requests/ }).click();
  await b.page.getByRole("button", { name: "Accept" }).first().click();
  await expect(a.page.getByText(`${b.name} accepted your friend request!`)).toBeVisible();
}

async function openChat(u: User, peer: string) {
  await u.page.getByRole("button", { name: "Active Link" }).click();
  await u.page
    .getByRole("button", { name: new RegExp(`^${peer.charAt(0).toUpperCase()}\\s*${peer}`) })
    .click({ timeout: 30_000 });
  await expect(u.page.getByRole("heading", { name: peer })).toBeVisible();
}

async function sendText(u: User, text: string) {
  const input = u.page.getByPlaceholder(/Secure message to/);
  await expect(input).toBeEnabled();
  await input.fill(text);
  await input.press("Enter");
  await expect(u.page.getByTestId("message").filter({ hasText: text })).toHaveCount(1);
}

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
    result.observed = bobGotPlaintext > 0 ? "plaintext delivered to Bob (LEAK)" : "no plaintext delivered to the wrong key";
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
