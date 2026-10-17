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
 * Bookkeeping lives in localStorage `krypt_spk_meta_<user>` (key ids and
 * times only, no key material): { current, retired: [{ id, retiredAt }] }.
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
/** Server limit per POST /api/prekeys. */
const MAX_OPKS_PER_REQUEST = 200;

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

export interface MaintenanceResult {
  uploadedSignedPrekey: boolean;
  uploadedOneTime: number;
  deletedSignedPrekeys: number;
}

/**
 * Brings the server's prekeys and the local private halves into the state
 * described above. Safe to call often: it does nothing when nothing is due.
 */
export function maintainPrekeys(p: Protocol, now = Date.now()): Promise<MaintenanceResult> {
  return appLock(`krypt-prekeys:${p.username}`, async () => {
    const result: MaintenanceResult = { uploadedSignedPrekey: false, uploadedOneTime: 0, deletedSignedPrekeys: 0 };
    const dsaSec = p.keys.dsaSecretKey;
    const meta = loadMeta(p.username);
    const status = await serverStatus();

    const currentRec = meta.current !== null ? await p.prekeys.getSignedPrekey(meta.current) : undefined;
    const rotate = !status.hasSignedPrekey || !currentRec || now - currentRec.createdAt >= SPK_ROTATE_MS;

    const upload: Partial<PrekeyUploadWire> = {};
    if (rotate) upload.signedPrekey = await createSignedPrekey(dsaSec, p.prekeys, now);

    // Refill to OPK_TARGET when low. If this device lost its prekey store, the
    // server still lists OPKs whose private halves are gone; peers that claim
    // them get UNKNOWN_PREKEY until those are used up (there is no delete API).
    if (status.oneTimeRemaining < OPK_LOW_WATERMARK) {
      const count = Math.min(OPK_TARGET - status.oneTimeRemaining, MAX_OPKS_PER_REQUEST);
      if (count > 0) upload.oneTimePrekeys = await createOneTimePrekeys(dsaSec, p.prekeys, count, now);
    }

    if (upload.signedPrekey || upload.oneTimePrekeys?.length) {
      const res = await apiPostJson("/api/prekeys", upload);
      if (!res.ok) {
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
