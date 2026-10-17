import { isKemSuite, type KemSuite } from "../crypto/pq";

/**
 * Per-user protocol settings, persisted in localStorage (they are preferences,
 * not secrets).
 *
 * - `krypt_suite_<user>`: ratchet suite for sessions this device INITIATES
 *   ("mlkem768" default, or "xwing"). Existing sessions keep the suite they
 *   were created with; the responder always follows the initiator (spec 11).
 */

export const DEFAULT_SUITE: KemSuite = "mlkem768";

const suiteKey = (user: string) => `krypt_suite_${user}`;

type Listener = (suite: KemSuite) => void;
const listeners = new Set<Listener>();

export function getSuite(user: string): KemSuite {
  try {
    const v = localStorage.getItem(suiteKey(user));
    return isKemSuite(v) ? v : DEFAULT_SUITE;
  } catch {
    return DEFAULT_SUITE;
  }
}

export function setSuite(user: string, suite: KemSuite): void {
  try {
    localStorage.setItem(suiteKey(user), suite);
  } catch {
    // Storage unavailable: the choice still applies to this page load.
  }
  listeners.forEach((l) => l(suite));
}

export function onSuiteChange(l: Listener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}
