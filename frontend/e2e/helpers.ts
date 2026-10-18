/**
 * Shared Playwright helpers: one browser context per user, console watching,
 * a toast recorder, and the v1 UI flow (register, befriend, open a chat, send).
 * The v0 attack spec uses only newUser/toasts; its UI flow is its own.
 */
import { expect, type Browser, type BrowserContext, type Page } from "@playwright/test";

export const PASSWORD = "correct horse battery staple";
export const VAULT_PASSWORD = "vault-password-123";

// 1x1 PNG (decodable by the browser; the app re-encodes it as JPEG).
export const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==",
  "base64",
);

export interface User {
  name: string;
  context: BrowserContext;
  page: Page;
  /** Non-log console lines matching the watch pattern, and page errors. */
  problems: string[];
  /** Decrypt error codes the client logged ("[Krypt] decrypt from x failed: CODE"). */
  codes: string[];
}

const DECRYPT_CODE = /\[Krypt\] decrypt from \S+ failed:\s*([A-Z_]+)/;

/** Watch `u.page`; call again after replacing the page. */
export function watch(u: User, problem: RegExp = /\[Krypt\]|\[KT\] ALERT/) {
  u.page.on("console", (msg) => {
    const t = msg.text();
    const m = DECRYPT_CODE.exec(t);
    if (m) u.codes.push(m[1]!);
    if (problem.test(t) && msg.type() !== "log") u.problems.push(`${msg.type()}: ${t}`);
  });
  u.page.on("pageerror", (err) => u.problems.push(`pageerror: ${err.message}`));
}

export interface NewUserOptions {
  userAgent?: string;
  /** Record every toast as it appears (toasts auto-dismiss); read with toasts(). */
  recordToasts?: boolean;
  /** Console pattern counted as a problem (default: [Krypt] lines and KT alerts). */
  problem?: RegExp;
}

export async function newUser(browser: Browser, name: string, o: NewUserOptions = {}): Promise<User> {
  const context = await browser.newContext({ acceptDownloads: true, ...(o.userAgent ? { userAgent: o.userAgent } : {}) });
  const page = await context.newPage();
  if (o.recordToasts) {
    await page.addInitScript(() => {
      const w = window as unknown as { __toasts: string[] };
      w.__toasts = [];
      const push = (el: Element) => {
        const t = (el.textContent ?? "").trim();
        // Toasts are short; skip large app-container blobs.
        if (t && t.length <= 400) w.__toasts.push(t);
      };
      const start = () => {
        new MutationObserver((muts) => {
          for (const mu of muts) mu.addedNodes.forEach((n) => n.nodeType === 1 && push(n as Element));
        }).observe(document.body, { childList: true, subtree: true });
      };
      if (document.body) start();
      else window.addEventListener("DOMContentLoaded", start);
    });
  }
  const u: User = { name, context, page, problems: [], codes: [] };
  watch(u, o.problem);
  return u;
}

/** Distinct recorded toasts matching `filter` (needs newUser(..., { recordToasts: true })). */
export async function toasts(u: User, filter: RegExp): Promise<string[]> {
  const raw = await u.page.evaluate(() => (window as unknown as { __toasts?: string[] }).__toasts ?? []);
  return Array.from(new Set(raw.filter((t) => filter.test(t))));
}

/** Register through the UI, pass the vault-backup gate; `ktBadge` is the badge text to expect, if any. */
export async function register(u: User, ktBadge?: string) {
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
  if (ktBadge) await expect(page.getByTestId("kt-badge")).toHaveText(ktBadge);
  else await expect(page.getByTestId("kt-badge")).toBeVisible();
}

export async function befriend(a: User, b: User) {
  await a.page.getByRole("button", { name: /^Requests/ }).click();
  await a.page.getByPlaceholder("Search global network...").fill(b.name);
  await a.page.getByRole("button", { name: "Invite" }).click();
  await b.page.getByRole("button", { name: /^Requests/ }).click();
  await b.page.getByRole("button", { name: "Accept" }).first().click();
  await expect(a.page.getByText(`${b.name} accepted your friend request!`)).toBeVisible();
}

export async function openChat(u: User, peer: string) {
  await u.page.getByRole("button", { name: "Active Link" }).click();
  try {
    await u.page.getByRole("button", { name: new RegExp(`^${peer.charAt(0).toUpperCase()}\\s*${peer}`) }).click({ timeout: 30_000 });
  } catch (e) {
    await u.page.screenshot({ path: `test-results/debug-${u.name}.png` });
    throw e;
  }
  await expect(u.page.getByRole("heading", { name: peer })).toBeVisible();
}

export async function sendText(u: User, text: string) {
  const input = u.page.getByPlaceholder(/Secure message to/);
  await expect(input).toBeEnabled();
  await input.fill(text);
  await input.press("Enter");
  await expect(u.page.getByTestId("message").filter({ hasText: text })).toHaveCount(1);
}
