/**
 * Large-file transfer end to end (spec 15): Alice offers files, Bob accepts,
 * chunks flow as binary frames through the real relay, Bob downloads and the
 * bytes match. Also: a zero-byte file with a hostile name (the download name
 * is cleaned), and a cancelled offer.
 *
 * Run: see e2e/README.md.
 */
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";
import { befriend, newUser, openChat, register, sendText, type User } from "./helpers";

const run = Date.now().toString(36).slice(-5);
const KT_BADGE = process.env.E2E_EXPECT_KT === "1" ? "KT verified" : "KT disabled";
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

const card = (page: Page, name: string) => page.getByTestId("file-transfer").filter({ hasText: name });

async function offer(u: User, name: string, buffer: Buffer) {
  await u.page.locator("#file-upload").setInputFiles({ name, mimeType: "application/octet-stream", buffer });
  await expect(card(u.page, name)).toBeVisible();
}

async function download(u: User, name: string): Promise<{ bytes: Buffer; suggested: string }> {
  const pending = u.page.waitForEvent("download");
  await card(u.page, name).getByRole("button", { name: "Download" }).click();
  const d = await pending;
  return { bytes: await readFile((await d.path())!), suggested: d.suggestedFilename() };
}

test("files: offer, accept, chunked transfer, download, cancel", async ({ browser }) => {
  const alice = await newUser(browser, `fa_${run}`);
  const bob = await newUser(browser, `fb_${run}`);
  await register(alice, KT_BADGE);
  await register(bob, KT_BADGE);
  await befriend(alice, bob);
  await openChat(alice, bob.name);
  await openChat(bob, alice.name);
  await sendText(alice, "hello before the files");

  // 1. 20 MB in 20 chunks of 1 MiB.
  const big = randomBytes(20 * 1024 * 1024);
  await offer(alice, "big.bin", big);
  await expect(card(bob.page, "big.bin")).toHaveAttribute("data-status", "offered");
  await card(bob.page, "big.bin").getByRole("button", { name: "Accept file" }).click();
  await expect(card(bob.page, "big.bin")).toHaveAttribute("data-status", "complete", { timeout: 120_000 });
  await expect(card(alice.page, "big.bin")).toHaveAttribute("data-status", "complete");
  const got = await download(bob, "big.bin");
  expect(got.suggested).toBe("big.bin");
  expect(got.bytes.length).toBe(big.length);
  expect(sha(got.bytes)).toBe(sha(big));

  // 2. Zero bytes, hostile name: one empty authenticated chunk; the saved name has no path.
  await offer(alice, "../../empty.html", Buffer.alloc(0));
  await card(bob.page, "empty.html").getByRole("button", { name: "Accept file" }).click();
  await expect(card(bob.page, "empty.html")).toHaveAttribute("data-status", "complete");
  const empty = await download(bob, "empty.html");
  expect(empty.bytes.length).toBe(0);
  expect(empty.suggested).toBe("_.._empty.html");

  // 3. Alice cancels before Bob answers: both sides show it cancelled, Bob cannot accept.
  await offer(alice, "cancel-me.bin", randomBytes(2 * 1024 * 1024));
  await expect(card(bob.page, "cancel-me.bin")).toHaveAttribute("data-status", "offered");
  await card(alice.page, "cancel-me.bin").getByRole("button", { name: "Cancel" }).click();
  await expect(card(alice.page, "cancel-me.bin")).toHaveAttribute("data-status", "cancelled");
  await expect(card(bob.page, "cancel-me.bin")).toHaveAttribute("data-status", "cancelled");
  await expect(card(bob.page, "cancel-me.bin").getByRole("button", { name: "Accept file" })).toHaveCount(0);

  expect(alice.problems).toEqual([]);
  expect(bob.problems).toEqual([]);
  expect([...alice.codes, ...bob.codes]).toEqual([]);
});
