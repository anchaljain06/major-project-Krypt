/**
 * Two users, real relay, real browser: Krypt v1 end to end.
 *
 * Alice and Bob register (prekeys are uploaded on registration), befriend,
 * exchange 10 text messages in each direction, an image and an audio clip,
 * then Bob goes offline and receives queued messages from the mailbox after
 * logging in again, and Alice refreshes her tab mid-conversation. Every
 * message must decrypt on the other side, both sides must show the same
 * safety number, and no decrypt error may be reported.
 *
 * Run: see e2e/README.md.
 */
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";

const run = Date.now().toString(36).slice(-5);
const ALICE = `alice_${run}`;
const BOB = `bob_${run}`;
const PASSWORD = "correct horse battery staple";
const VAULT_PASSWORD = "vault-password-123";
/** Set E2E_EXPECT_KT=1 when the frontend was built with VITE_KT_LOG_PUBKEY and the backend serves /kt/*. */
const EXPECT_KT = process.env.E2E_EXPECT_KT === "1";

// 1x1 PNG (decodable by the browser; the app re-encodes it as JPEG).
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==",
  "base64",
);

/** A short silent 8 kHz mono WAV. */
function wav(samples = 8000): Buffer {
  const b = Buffer.alloc(44 + samples);
  b.write("RIFF", 0);
  b.writeUInt32LE(36 + samples, 4);
  b.write("WAVEfmt ", 8);
  b.writeUInt32LE(16, 16);
  b.writeUInt16LE(1, 20);
  b.writeUInt16LE(1, 22);
  b.writeUInt32LE(8000, 24);
  b.writeUInt32LE(8000, 28);
  b.writeUInt16LE(1, 32);
  b.writeUInt16LE(8, 34);
  b.write("data", 36);
  b.writeUInt32LE(samples, 40);
  b.fill(128, 44);
  return b;
}

const ERROR_PATTERN =
  /Could not decrypt|Dropped a|failed authentication|Legacy v0|not trusted|ALERT|attachment from .* was dropped|Secure messaging could not start|Could not publish your prekeys/;

interface User {
  name: string;
  context: BrowserContext;
  page: Page;
  problems: string[];
}

function watch(page: Page, problems: string[]) {
  page.on("console", (msg) => {
    const t = msg.text();
    if (/\[Krypt\]|\[KT\] ALERT/.test(t) && msg.type() !== "log") problems.push(`${msg.type()}: ${t}`);
  });
  page.on("pageerror", (err) => problems.push(`pageerror: ${err.message}`));
}

async function newUser(browser: Browser, name: string): Promise<User> {
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  const problems: string[] = [];
  watch(page, problems);
  return { name, context, page, problems };
}

async function register(u: User) {
  const { page } = u;
  await page.goto("/");
  await page.getByRole("button", { name: "New here? Establish identity." }).click();
  await page.getByPlaceholder("Enter your alias").fill(u.name);
  await page.getByPlaceholder("Enter your secure password").fill(PASSWORD);
  await page.getByRole("button", { name: "Generate Proofs & Register" }).click();
  // Vault backup gate after registration.
  await page.getByPlaceholder(/Vault password \(min/).fill(VAULT_PASSWORD);
  await page.getByPlaceholder("Confirm vault password").fill(VAULT_PASSWORD);
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download Encrypted Vault" }).click();
  await download;
  await page.getByRole("button", { name: "I saved it, continue" }).click();
  await expect(page.getByTestId("kt-badge")).toHaveText(EXPECT_KT ? "KT verified" : "KT disabled");
}

/** Login on a device that already holds the password-encrypted identity (no vault file). */
async function login(u: User) {
  const { page } = u;
  await page.goto("/");
  await page.getByPlaceholder("Enter your alias").fill(u.name);
  await page.getByPlaceholder("Enter your secure password").fill(PASSWORD);
  await page.getByRole("button", { name: "Secure Login" }).click();
  await expect(page.getByTestId("kt-badge")).toBeVisible();
}

async function openChat(u: User, peer: string) {
  await u.page.getByRole("button", { name: "Active Link" }).click();
  try {
    await u.page.getByRole("button", { name: new RegExp(`^${peer.charAt(0).toUpperCase()}\\s*${peer}`) }).click({ timeout: 30_000 });
  } catch (e) {
    await u.page.screenshot({ path: `test-results/debug-${u.name}.png` });
    throw e;
  }
  await expect(u.page.getByRole("heading", { name: peer })).toBeVisible();
}

async function sendText(u: User, text: string) {
  const input = u.page.getByPlaceholder(/Secure message to/);
  await expect(input).toBeEnabled();
  await input.fill(text);
  await input.press("Enter");
  await expect(u.page.getByTestId("message").filter({ hasText: text })).toHaveCount(1);
}

async function expectReceived(u: User, from: string, text: string) {
  await expect(u.page.locator(`[data-testid="message"][data-from="${from}"]`).filter({ hasText: text })).toHaveCount(1);
}

async function safetyDigits(u: User): Promise<string> {
  await u.page.getByRole("button", { name: "Security" }).click();
  const sn = u.page.getByTestId("safety-number");
  await expect(sn).toBeVisible();
  const digits = (await sn.innerText()).replace(/\s+/g, " ").trim();
  await expect(u.page.getByTestId("session-status")).toContainText("ML-KEM-768");
  if (EXPECT_KT) await expect(u.page.getByTestId("kt-peer-status")).toHaveText("Verified");
  await u.page.getByRole("button", { name: "Close" }).click();
  return digits;
}

function assertClean(u: User) {
  expect(u.problems, `${u.name} console problems`).toEqual([]);
}

test("two users chat over Krypt v1 through the relay", async ({ browser }) => {
  const alice = await newUser(browser, ALICE);
  const bob = await newUser(browser, BOB);

  await test.step("register both users", async () => {
    await register(alice);
    await register(bob);
  });

  await test.step("befriend", async () => {
    await alice.page.getByRole("button", { name: /^Requests/ }).click();
    await alice.page.getByPlaceholder("Search global network...").fill(BOB);
    await alice.page.getByRole("button", { name: "Invite" }).click();
    await bob.page.getByRole("button", { name: /^Requests/ }).click();
    await bob.page.getByRole("button", { name: "Accept" }).first().click();
    await expect(alice.page.getByText(`${BOB} accepted your friend request!`)).toBeVisible();
  });

  await test.step("10 text messages in each direction", async () => {
    await openChat(alice, BOB);
    await openChat(bob, ALICE);
    for (let i = 0; i < 10; i++) {
      await sendText(alice, `hello bob #${i}`);
      await expectReceived(bob, ALICE, `hello bob #${i}`);
      await sendText(bob, `hi alice #${i}`);
      await expectReceived(alice, BOB, `hi alice #${i}`);
    }
  });

  await test.step("image and audio", async () => {
    await alice.page.locator("#image-upload").setInputFiles({ name: "dot.png", mimeType: "image/png", buffer: PNG });
    const img = bob.page.locator(`[data-testid="message"][data-from="${ALICE}"][data-type="image"] img`);
    await expect(img).toHaveCount(1);
    expect(await img.getAttribute("src")).toMatch(/^data:image\/jpeg;base64,/);

    await bob.page.locator("#audio-upload").setInputFiles({ name: "beep.wav", mimeType: "audio/wav", buffer: wav() });
    const audio = alice.page.locator(`[data-testid="message"][data-from="${BOB}"][data-type="audio"] audio`);
    await expect(audio).toHaveCount(1);
    expect(await audio.getAttribute("src")).toMatch(/^data:audio\/wav;base64,/);
  });

  await test.step("safety numbers match", async () => {
    const a = await safetyDigits(alice);
    const b = await safetyDigits(bob);
    expect(a).toMatch(/^(\d{5} ){11}\d{5}$/);
    expect(a).toBe(b);
  });

  await test.step("Bob offline: messages wait in the mailbox", async () => {
    assertClean(bob);
    await bob.page.close();
    await expect(alice.page.getByText("Offline", { exact: false }).first()).toBeVisible();
    for (let i = 0; i < 3; i++) await sendText(alice, `while you were away #${i}`);
    await expect(alice.page.getByText(`queued for ${BOB} (offline)`).first()).toBeVisible();
    bob.page = await bob.context.newPage();
    watch(bob.page, bob.problems);
    await login(bob);
    await openChat(bob, ALICE);
    for (let i = 0; i < 3; i++) await expectReceived(bob, ALICE, `while you were away #${i}`);
    await sendText(bob, "back online");
    await expectReceived(alice, BOB, "back online");
  });

  await test.step("Alice refreshes her tab mid-conversation", async () => {
    await alice.page.reload();
    await expect(alice.page.getByTestId("kt-badge")).toBeVisible();
    await openChat(alice, BOB);
    // History is still readable and the ratchet state survived the refresh.
    await expectReceived(alice, BOB, "hi alice #9");
    await sendText(alice, "after refresh");
    await expectReceived(bob, ALICE, "after refresh");
    await sendText(bob, "reply after refresh");
    await expectReceived(alice, BOB, "reply after refresh");
  });

  await test.step("hybrid toggle: a new session uses X-Wing", async () => {
    await alice.page.getByRole("button", { name: "Settings" }).click();
    await alice.page.getByTestId("suite-toggle").check();
    await alice.page.getByRole("button", { name: "Settings" }).click();
    alice.page.once("dialog", (d) => d.accept());
    await alice.page.getByRole("button", { name: "Security" }).click();
    await alice.page.getByRole("button", { name: "Reset session" }).click();
    await expect(alice.page.getByText("No session yet")).toBeVisible();
    await alice.page.getByRole("button", { name: "Close" }).click();
    await sendText(alice, "now over x-wing");
    await expectReceived(bob, ALICE, "now over x-wing");
    await sendText(bob, "x-wing reply");
    await expectReceived(alice, BOB, "x-wing reply");
    for (const u of [alice, bob]) {
      await u.page.getByRole("button", { name: "Security" }).click();
      await expect(u.page.getByTestId("session-status")).toContainText("X-Wing");
      await u.page.getByRole("button", { name: "Close" }).click();
    }
  });

  await test.step("everything decrypted, nothing reported", async () => {
    // From Alice: 10 + 3 (mailbox) + 1 (after refresh) + 1 (x-wing) texts and 1 image.
    // From Bob: 10 + 1 (back online) + 1 (after refresh) + 1 (x-wing) texts and 1 audio clip.
    await expect(bob.page.locator(`[data-testid="message"][data-from="${ALICE}"]`)).toHaveCount(16);
    await expect(alice.page.locator(`[data-testid="message"][data-from="${BOB}"]`)).toHaveCount(14);
    for (const u of [alice, bob]) {
      await expect(u.page.getByText(ERROR_PATTERN)).toHaveCount(0);
      assertClean(u);
    }
  });

  await alice.context.close();
  await bob.context.close();
});
