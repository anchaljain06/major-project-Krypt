/**
 * App-layer messaging state that must survive a refresh (services/messaging.ts):
 *
 * - Resend outbox, per peer: messages sent on a session the peer has not
 *   confirmed yet, re-sent if the peer turns out to have kept a different
 *   session (spec 4.5). { sessionId, items[] }, at most MAX_OUTBOX_ITEMS.
 * - Seen message ids, per peer: application message ids already stored, so a
 *   re-sent copy is dropped. The newest MAX_SEEN_PER_PEER are kept.
 *
 * Both live in IndexedDB "krypt-msgstate-v1:<user>", sealed with the same
 * store key and scheme as the session store (spec 12): AES-256-GCM, random
 * IV, AAD = lp(label, peer) with labels "krypt-outbox-v1" and "krypt-seen-v1",
 * so a record cannot be moved to another peer's slot or between the two
 * kinds. Read-modify-write runs under a per-peer lock (navigator.locks in the
 * app), so two tabs never lose each other's updates and only one of them
 * takes an outbox for re-sending.
 */
import type { AppMessage, ChatContentType } from "../crypto/appMessage";
import { fromBase64url, fromUtf8, lp, toBase64url, utf8 } from "../crypto/encoding";
import { createMutexLock, type LockFn } from "../crypto/session";
import { done, open, openDb, req, seal, type Sealed } from "../crypto/session-store";

export const MAX_OUTBOX_ITEMS = 200;
export const MAX_SEEN_PER_PEER = 2000;

const OUTBOX_LABEL = "krypt-outbox-v1";
const SEEN_LABEL = "krypt-seen-v1";

/** One message waiting for its session to be confirmed. */
export interface OutgoingItem {
  contentType: ChatContentType;
  msg: AppMessage;
  /** Encrypted attachment bytes (already sealed under the attachment key). */
  attachment?: Uint8Array;
}

export interface OutboxEntry {
  sessionId: string;
  items: OutgoingItem[];
}

export interface MessageStateOptions {
  key: CryptoKey;
  dbName: string;
  indexedDB?: IDBFactory;
  lock?: LockFn;
}

interface OutboxJson {
  sessionId: string;
  items: { contentType: ChatContentType; msg: AppMessage; attachment?: string }[];
}

export class IndexedDbMessageState {
  private db: Promise<IDBDatabase>;
  private key: CryptoKey;
  private lock: LockFn;
  private name: string;

  constructor(opts: MessageStateOptions) {
    this.key = opts.key;
    this.lock = opts.lock ?? createMutexLock();
    this.name = opts.dbName;
    this.db = openDb(opts.indexedDB ?? globalThis.indexedDB, opts.dbName, ["outbox", "seen"]);
  }

  private locked<T>(peer: string, fn: () => Promise<T>): Promise<T> {
    return this.lock(`krypt-msgstate:${this.name}:${peer}`, fn);
  }

  private async get(store: "outbox" | "seen", label: string, peer: string): Promise<Uint8Array | undefined> {
    const sealed = await req<Sealed | undefined>((await this.db).transaction(store).objectStore(store).get(peer));
    return sealed ? open(this.key, lp(label, peer), sealed) : undefined;
  }

  private async put(store: "outbox" | "seen", label: string, peer: string, data: Uint8Array | null): Promise<void> {
    const sealed = data ? await seal(this.key, lp(label, peer), data) : null;
    const tx = (await this.db).transaction(store, "readwrite");
    if (sealed) tx.objectStore(store).put(sealed, peer);
    else tx.objectStore(store).delete(peer);
    await done(tx);
  }

  // -------------------------------------------------------------------------
  // Outbox

  private async readOutbox(peer: string): Promise<OutboxEntry | undefined> {
    const raw = await this.get("outbox", OUTBOX_LABEL, peer);
    if (!raw) return undefined;
    const j = JSON.parse(fromUtf8(raw)) as OutboxJson;
    return {
      sessionId: j.sessionId,
      items: j.items.map((i) => ({
        contentType: i.contentType,
        msg: i.msg,
        ...(i.attachment !== undefined ? { attachment: fromBase64url(i.attachment) } : {}),
      })),
    };
  }

  private writeOutbox(peer: string, box: OutboxEntry | null): Promise<void> {
    if (!box) return this.put("outbox", OUTBOX_LABEL, peer, null);
    const j: OutboxJson = {
      sessionId: box.sessionId,
      items: box.items.map((i) => ({
        contentType: i.contentType,
        msg: i.msg,
        ...(i.attachment ? { attachment: toBase64url(i.attachment) } : {}),
      })),
    };
    return this.put("outbox", OUTBOX_LABEL, peer, utf8(JSON.stringify(j)));
  }

  /** Current outbox for `peer` (read-only view). */
  peekOutbox(peer: string): Promise<OutboxEntry | undefined> {
    return this.readOutbox(peer);
  }

  /** Adds `item` to the outbox of `sessionId`, replacing an outbox kept for another session. */
  appendOutbox(peer: string, sessionId: string, item: OutgoingItem): Promise<void> {
    return this.locked(peer, async () => {
      const box = await this.readOutbox(peer);
      const items = box && box.sessionId === sessionId ? [...box.items, item] : [item];
      await this.writeOutbox(peer, { sessionId, items: items.slice(-MAX_OUTBOX_ITEMS) });
    });
  }

  /** Removes and returns the outbox (only one caller, in any tab, gets it). */
  takeOutbox(peer: string): Promise<OutboxEntry | undefined> {
    return this.locked(peer, async () => {
      const box = await this.readOutbox(peer);
      if (box) await this.writeOutbox(peer, null);
      return box;
    });
  }

  clearOutbox(peer: string): Promise<void> {
    return this.locked(peer, () => this.writeOutbox(peer, null));
  }

  // -------------------------------------------------------------------------
  // Seen message ids

  private async readSeen(peer: string): Promise<string[]> {
    const raw = await this.get("seen", SEEN_LABEL, peer);
    return raw ? (JSON.parse(fromUtf8(raw)) as string[]) : [];
  }

  async hasSeen(peer: string, msgId: string): Promise<boolean> {
    return (await this.readSeen(peer)).includes(msgId);
  }

  markSeen(peer: string, msgId: string): Promise<void> {
    return this.locked(peer, async () => {
      const ids = await this.readSeen(peer);
      if (ids.includes(msgId)) return;
      ids.push(msgId);
      await this.put("seen", SEEN_LABEL, peer, utf8(JSON.stringify(ids.slice(-MAX_SEEN_PER_PEER))));
    });
  }

  async close(): Promise<void> {
    (await this.db).close();
  }
}
