/**
 * Identity trust for the SessionManager's trustIdentity hook (spec 3.1, plan
 * 3.1 and 3.4). Called once per handshake, inside the per-peer lock.
 *
 *   1. Key transparency: the peer's ML-DSA key must be the one in the log
 *      (services/kt.ts). A failed proof is an ALERT and the key is refused.
 *      "Not in the log" (fresh account, lazy tree head, or KT disabled) falls
 *      back to step 2 alone.
 *   2. TOFU pin in the local contacts store: the first key seen is pinned. A
 *      different key opens a blocking dialog; only an explicit "accept"
 *      re-pins it, and the change is recorded in the contact.
 */
import toast from "react-hot-toast";
import { ctEqual, fromBase64Std, toBase64Std } from "../crypto/encoding";
import { decryptLocal, encryptLocal } from "../crypto/localStore";
import type { UserIdentityKeys } from "../crypto/mlkem";
import { keyFingerprint } from "../crypto/safetyNumber";
import { sha256Hex } from "../crypto/utils";
import { db } from "./db";
import { askIdentityChange } from "./identityPrompt";
import type { KtClient, KtPeerState } from "./kt";

export interface ContactRecord {
  username: string;
  /** ML-DSA-87 identity key, standard base64 (v1 contacts). */
  dsa?: string;
  /** Legacy: the whole identityKey JSON pinned by v0 builds. */
  publicKey?: string;
  pinnedAt?: number;
  /** Accepted identity-key changes, oldest first. */
  keyChanges?: { at: number; from: string; to: string }[];
}

const contactId = (username: string) => sha256Hex(username);

export async function loadContact(username: string, keys: UserIdentityKeys): Promise<ContactRecord | null> {
  const row = await db.contacts.get(await contactId(username));
  if (!row) return null;
  // Fail closed: an unreadable pin must not silently become "no pin".
  return JSON.parse(await decryptLocal(row.payload, keys)) as ContactRecord;
}

async function saveContact(rec: ContactRecord, keys: UserIdentityKeys) {
  await db.contacts.put({ id: await contactId(rec.username), payload: await encryptLocal(JSON.stringify(rec), keys) });
}

/** The pinned ML-DSA key of a contact, or null if none is pinned. */
export function pinnedDsa(rec: ContactRecord): Uint8Array | null {
  try {
    if (rec.dsa) return fromBase64Std(rec.dsa);
    if (rec.publicKey) {
      const dsa = (JSON.parse(rec.publicKey) as { dsa?: unknown }).dsa;
      if (typeof dsa === "string" && dsa.length > 0) return fromBase64Std(dsa);
    }
  } catch {
    // Unparseable legacy pin: treat as no ML-DSA pin.
  }
  return null;
}

function ktNote(s: KtPeerState): string {
  switch (s.state) {
    case "verified":
      return `The new key is in the key transparency log (key version ${s.keyVersion}).`;
    case "not-in-log":
      return "The new key is not in the key transparency log yet.";
    case "disabled":
      return "Key transparency is disabled in this build, so the server's claim cannot be checked.";
    default:
      return "Key transparency could not check the new key.";
  }
}

export function createTrustIdentity(keys: UserIdentityKeys, kt: KtClient) {
  return async (peer: string, dsaPub: Uint8Array): Promise<boolean> => {
    const ktState = await kt.verifyPeer(peer, dsaPub);
    if (ktState.state === "alert") {
      toast.error(`Key transparency ALERT for ${peer}: ${ktState.reason}`, { duration: 10_000 });
      return false;
    }
    if (ktState.state === "error") {
      toast.error(`Cannot verify ${peer}'s identity key: ${ktState.reason}`);
      return false;
    }

    let contact: ContactRecord | null;
    try {
      contact = await loadContact(peer, keys);
    } catch {
      toast.error(`Stored contact record for ${peer} could not be read. Refusing the session.`);
      return false;
    }
    const pinned = contact ? pinnedDsa(contact) : null;
    const now = Date.now();
    if (!pinned) {
      await saveContact({ ...(contact ?? {}), username: peer, dsa: toBase64Std(dsaPub), pinnedAt: now }, keys);
      return true;
    }
    if (ctEqual(pinned, dsaPub)) return true;

    const from = await keyFingerprint(pinned);
    const to = await keyFingerprint(dsaPub);
    const accepted = await askIdentityChange({ peer, oldFingerprint: from, newFingerprint: to, ktNote: ktNote(ktState) });
    if (!accepted) {
      toast.error(`${peer}'s new identity key was rejected. No session was started.`);
      return false;
    }
    await saveContact(
      {
        ...contact!,
        username: peer,
        dsa: toBase64Std(dsaPub),
        publicKey: undefined,
        pinnedAt: now,
        keyChanges: [...(contact!.keyChanges ?? []), { at: now, from, to }],
      },
      keys,
    );
    return true;
  };
}
