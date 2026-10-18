/**
 * Prekey upload, refill and signed-prekey rotation (plan 1.5, spec 3).
 *
 * Runs on registration, on every login/restore, when the server sends
 * `prekeys_low`, and on a timer. One run at a time per user across tabs
 * (navigator.locks), so two tabs never both upload.
 *
 * Signed prekey lifecycle (spec 3.2):
 * - a new SPK is uploaded when the server has none, when this device does not
 *   hold the private half of the current one, or when it is SPK_ROTATE_MS old;
 * - the replaced SPK's private key is kept for SPK_GRACE_MS after its
 *   replacement was uploaded, so inits already in flight still complete, and
 *   then deleted together with its session-id memory. This bounds the epoch-0
 *   exposure of SPK-only sessions to about three weeks.
 *
 * One-time prekey hygiene:
 * - Stale OPKs. Every OPK on the server should have its private half here
 *   (this device may hold more: OPKs already claimed whose init has not
 *   arrived). If the server lists more OPKs than this device holds, the
 *   prekey store was lost (e.g. cleared IndexedDB), and every init that uses
 *   one of the orphans fails here with UNKNOWN_PREKEY. Then all server OPKs
 *   are withdrawn (DELETE /api/prekeys/one-time) and a fresh batch is
 *   uploaded. Local private halves are kept: some may belong to OPKs already
 *   claimed by a peer whose init is still on its way. The same
 *   reset runs when an incoming init names an OPK we do not hold
 *   (`resetOneTimePrekeysAfterUnknown`). Resets are rate-limited, because an
 *   init naming an unknown OPK cannot be authenticated and anyone on the
 *   path could forge one.
 * - Failed uploads. OPK private halves generated for an upload that failed
 *   are deleted again. If the server did store them (response lost), the
 *   count check above withdraws the orphans on the next run.
 *
 * Bookkeeping lives in localStorage `krypt_spk_meta_<user>` (key ids and
 * times only, no key material): { current, retired: [{ id, retiredAt }] },
 * and `krypt_opk_reset_<user>` (time of the last OPK reset).
 */
import { createOneTimePrekeys, createSignedPrekey, type PrekeyUploadWire } from "../crypto/prekeys";
import { apiFetch, apiPostJson } from "./api";
import { appLock, type Protocol } from "./protocol";

const DAY = 24 * 60 * 60 * 1000;
export const SPK_ROTATE_MS = 7 * DAY;
export const SPK_GRACE_MS = 14 * DAY;
/** Server sends prekeys_low below this (primary-backend PREKEYS_LOW_WATERMARK). */
export const OPK_LOW_WATERMARK = 20;
export const OPK_TARGET = 100;
/** At most one withdraw-and-replace of all server OPKs per this interval. */
export const OPK_RESET_MIN_INTERVAL_MS = 60 * 60 * 1000;
/** Server limit per POST /api/prekeys. */
const MAX_OPKS_PER_REQUEST = 200;

const resetKey = (user: string) => `krypt_opk_reset_${user}`;

function lastReset(user: string): number {
  try {
    const v = Number(localStorage.getItem(resetKey(user)));
    return Number.isFinite(v) ? v : 0;
  } catch {
    return 0;
  }
}

function noteReset(user: string, now: number) {
  try {
    localStorage.setItem(resetKey(user), String(now));
  } catch {
    // Storage unavailable: the rate limit just does not persist.
  }
}

interface SpkMeta {
  current: number | null;
  retired: { id: number; retiredAt: number }[];
}

const metaKey = (user: string) => `krypt_spk_meta_${user}`;

function loadMeta(user: string): SpkMeta {
  try {
    const raw = JSON.parse(localStorage.getItem(metaKey(user)) ?? "null");
    if (raw && typeof raw === "object" && Array.isArray(raw.retired)) {
      return {
        current: Number.isInteger(raw.current) ? raw.current : null,
        retired: raw.retired.filter(
          (r: unknown): r is SpkMeta["retired"][number] =>
            !!r && typeof r === "object" && Number.isInteger((r as { id: unknown }).id) && typeof (r as { retiredAt: unknown }).retiredAt === "number",
        ),
      };
    }
  } catch {
    // fall through
  }
  return { current: null, retired: [] };
}

function saveMeta(user: string, meta: SpkMeta) {
  localStorage.setItem(metaKey(user), JSON.stringify(meta));
}

export interface PrekeyStatus {
  oneTimeRemaining: number;
  hasSignedPrekey: boolean;
}

async function serverStatus(): Promise<PrekeyStatus> {
  const res = await apiFetch("/api/prekeys/count");
  if (!res.ok) throw new Error(`prekey status failed (HTTP ${res.status})`);
  const j = await res.json();
  return { oneTimeRemaining: Number(j.oneTimeRemaining) || 0, hasSignedPrekey: !!j.hasSignedPrekey };
}

/** DELETE /api/prekeys/one-time without keyIds: withdraws all of our OPKs. Returns what is left (0). */
async function withdrawAllOneTimePrekeys(): Promise<number> {
  const res = await apiFetch("/api/prekeys/one-time", { method: "DELETE" });
  if (!res.ok) throw new Error(`one-time prekey withdrawal failed (HTTP ${res.status})`);
  const j = await res.json();
  return Number(j.oneTimeRemaining) || 0;
}

export interface MaintenanceOptions {
  /** Withdraw every server OPK and upload a fresh batch (subject to the rate limit). */
  resetOneTime?: boolean;
}

export interface MaintenanceResult {
  uploadedSignedPrekey: boolean;
  uploadedOneTime: number;
  deletedSignedPrekeys: number;
  /** All server OPKs were withdrawn before the refill. */
  resetOneTime: boolean;
}

/**
 * Brings the server's prekeys and the local private halves into the state
 * described above. Safe to call often: it does nothing when nothing is due.
 */
export function maintainPrekeys(p: Protocol, now = Date.now(), opts: MaintenanceOptions = {}): Promise<MaintenanceResult> {
  return appLock(`krypt-prekeys:${p.username}`, async () => {
    const result: MaintenanceResult = {
      uploadedSignedPrekey: false,
      uploadedOneTime: 0,
      deletedSignedPrekeys: 0,
      resetOneTime: false,
    };
    const dsaSec = p.keys.dsaSecretKey;
    const meta = loadMeta(p.username);
    const status = await serverStatus();

    const currentRec = meta.current !== null ? await p.prekeys.getSignedPrekey(meta.current) : undefined;
    const rotate = !status.hasSignedPrekey || !currentRec || now - currentRec.createdAt >= SPK_ROTATE_MS;

    // Stale OPKs: the server lists more than this device can answer for, or a
    // peer's init named one we do not hold. Withdraw them all, then refill.
    const lostHalves = status.oneTimeRemaining > (await p.prekeys.countOneTimePrekeys());
    if ((lostHalves || opts.resetOneTime) && now - lastReset(p.username) >= OPK_RESET_MIN_INTERVAL_MS) {
      status.oneTimeRemaining = await withdrawAllOneTimePrekeys();
      noteReset(p.username, now);
      result.resetOneTime = true;
    }

    const upload: Partial<PrekeyUploadWire> = {};
    if (rotate) upload.signedPrekey = await createSignedPrekey(dsaSec, p.prekeys, now);

    // Refill to OPK_TARGET when low.
    if (status.oneTimeRemaining < OPK_LOW_WATERMARK) {
      const count = Math.min(OPK_TARGET - status.oneTimeRemaining, MAX_OPKS_PER_REQUEST);
      if (count > 0) upload.oneTimePrekeys = await createOneTimePrekeys(dsaSec, p.prekeys, count, now);
    }

    if (upload.signedPrekey || upload.oneTimePrekeys?.length) {
      // A failed upload leaves no OPK private halves behind. (A new SPK left
      // behind is collected as an orphan after SPK_GRACE_MS, below.)
      const discardOneTime = async () => {
        for (const k of upload.oneTimePrekeys ?? []) await p.prekeys.deleteOneTimePrekey(k.keyId);
      };
      let res: Response;
      try {
        res = await apiPostJson("/api/prekeys", upload);
      } catch (err) {
        await discardOneTime();
        throw err;
      }
      if (!res.ok) {
        await discardOneTime();
        const err = await res.json().catch(() => ({}));
        throw new Error(`prekey upload failed: ${err.error ?? `HTTP ${res.status}`}`);
      }
      if (upload.signedPrekey) {
        if (meta.current !== null && meta.current !== upload.signedPrekey.keyId) {
          meta.retired.push({ id: meta.current, retiredAt: now });
        }
        meta.current = upload.signedPrekey.keyId;
        result.uploadedSignedPrekey = true;
      }
      result.uploadedOneTime = upload.oneTimePrekeys?.length ?? 0;
      saveMeta(p.username, meta);
    }

    // Garbage-collect signed prekeys: retired ones after the grace period, and
    // orphans (generated but never confirmed as current, e.g. a failed upload)
    // once they are older than the grace period.
    const retired = new Map(meta.retired.map((r) => [r.id, r.retiredAt]));
    for (const id of await p.prekeys.listSignedPrekeyIds()) {
      if (id === meta.current) continue;
      const retiredAt = retired.get(id);
      let expired: boolean;
      if (retiredAt !== undefined) {
        expired = now - retiredAt >= SPK_GRACE_MS;
      } else {
        const rec = await p.prekeys.getSignedPrekey(id);
        expired = !rec || now - rec.createdAt >= SPK_GRACE_MS;
      }
      if (expired) {
        await p.prekeys.deleteSignedPrekey(id);
        retired.delete(id);
        result.deletedSignedPrekeys++;
      }
    }
    const kept = meta.retired.filter((r) => retired.has(r.id));
    if (kept.length !== meta.retired.length) saveMeta(p.username, { ...meta, retired: kept });
    return result;
  });
}

/**
 * Called when an incoming init named a one-time prekey this device does not
 * hold (UNKNOWN_PREKEY): the server is handing out OPKs we cannot answer, so
 * withdraw them all and upload fresh ones. Returns null when rate-limited.
 */
export async function resetOneTimePrekeysAfterUnknown(p: Protocol, now = Date.now()): Promise<MaintenanceResult | null> {
  if (now - lastReset(p.username) < OPK_RESET_MIN_INTERVAL_MS) return null;
  return maintainPrekeys(p, now, { resetOneTime: true });
}
