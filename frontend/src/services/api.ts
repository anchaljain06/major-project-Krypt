import { getToken } from "./authToken";

const API_URL = import.meta.env.VITE_API_URL;

/** Thrown by apiFetch when the server rejects the session token (HTTP 401). */
export class SessionExpiredError extends Error {
  constructor() {
    super("Session expired");
    this.name = "SessionExpiredError";
  }
}

type UnauthorizedHandler = () => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;

/** Registers the callback that logs the user out when the token is rejected. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null) {
  unauthorizedHandler = handler;
}

/** Invokes the registered logout callback (used by REST and socket auth failures). */
export function notifyUnauthorized() {
  unauthorizedHandler?.();
}

/**
 * fetch() wrapper for the Krypt REST API.
 * - Prefixes `path` with VITE_API_URL (pass paths like "/api/friends/alice").
 * - Adds `Authorization: Bearer <token>` when a session token exists.
 * - On 401 for a request that carried a token, triggers logout and throws
 *   SessionExpiredError. Login/registration calls run without a token, so a
 *   401 there (e.g. wrong password) is returned to the caller as usual.
 */
export async function apiFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(`${API_URL}${path}`, { ...init, headers });

  if (res.status === 401 && token) {
    notifyUnauthorized();
    throw new SessionExpiredError();
  }
  return res;
}

/** Convenience for JSON POST bodies. */
export function apiPostJson(path: string, body: unknown): Promise<Response> {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
