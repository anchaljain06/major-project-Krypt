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
import { expect, test } from "@playwright/test";
import { PASSWORD, PNG, befriend, newUser, openChat, register, sendText, watch, type User } from "./helpers";

const run = Date.now().toString(36).slice(-5);
const ALICE = `alice_${run}`;
const BOB = `bob_${run}`;
/** Set E2E_EXPECT_KT=1 when the frontend was built with VITE_KT_LOG_PUBKEY and the backend serves /kt/*. */
const EXPECT_KT = process.env.E2E_EXPECT_KT === "1";
const KT_BADGE = EXPECT_KT ? "KT verified" : "KT disabled";

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

/** Login on a device that already holds the password-encrypted identity (no vault file). */
async function login(u: User) {
  const { page } = u;
  await page.goto("/");
  await page.getByPlaceholder("Enter your alias").fill(u.name);
  await page.getByPlaceholder("Enter your secure password").fill(PASSWORD);
  await page.getByRole("button", { name: "Secure Login" }).click();
  await expect(page.getByTestId("kt-badge")).toBeVisible();
}

async function expectReceived(u: User, from: string, text: string) {
  await expect(u.page.locator(`[data-testid="message"][data-from="${from}"]`).filter({ hasText: text })).toHaveCount(1);
}

async function safetyDigits(u: User): Promise<string> {
  await u.page.getByRole("button", { name: "Security" }).click();
  const sn = u.page.getByTestId("safety-number");
  await expect(sn).toBeVisible();
  const digits = (await sn.innerText()).replace(/\s+/g, " ").trim();
  await expect(u.page.getByTestId("session-status")).toContainText("ML-KEM-1024");
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
    await register(alice, KT_BADGE);
    await register(bob, KT_BADGE);
  });

  await test.step("befriend", () => befriend(alice, bob));

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
    watch(bob);
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

  await test.step("everything decrypted, nothing reported", async () => {
    // From Alice: 10 + 3 (mailbox) + 1 (after refresh) texts and 1 image.
    // From Bob: 10 + 1 (back online) + 1 (after refresh) texts and 1 audio clip.
    await expect(bob.page.locator(`[data-testid="message"][data-from="${ALICE}"]`)).toHaveCount(15);
    await expect(alice.page.locator(`[data-testid="message"][data-from="${BOB}"]`)).toHaveCount(13);
    for (const u of [alice, bob]) {
      await expect(u.page.getByText(ERROR_PATTERN)).toHaveCount(0);
      assertClean(u);
    }
  });

  await alice.context.close();
  await bob.context.close();
});
