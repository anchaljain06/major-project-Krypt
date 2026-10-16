/**
 * Short-lived server session token (issued by /api/login/verify and /api/register).
 *
 * Held in memory and mirrored to sessionStorage ("krypt_token") so that a page
 * refresh inside the same tab keeps the session. sessionStorage is per-tab and
 * is cleared when the tab closes; the token is never written to localStorage.
 */

const TOKEN_STORAGE_KEY = "krypt_token";

let memoryToken: string | null = null;

export function getToken(): string | null {
  if (memoryToken) return memoryToken;
  try {
    memoryToken = sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    memoryToken = null;
  }
  return memoryToken;
}

export function setToken(token: string): void {
  memoryToken = token;
  try {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
  } catch {
    // Storage unavailable: the token still lives in memory for this page load.
  }
}

export function clearToken(): void {
  memoryToken = null;
  try {
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Ignore: nothing to clear.
  }
}
