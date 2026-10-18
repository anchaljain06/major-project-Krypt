/**
 * Local state for file transfers (spec 15.5), IndexedDB "krypt-files-v1:<user>":
 *
 * - transfers: one record per transfer (manifest with the file key, status,
 *   bitmap), sealed with the store key like the session store (spec 12),
 *   AAD = lp("krypt-file-transfer-v1", transferId).
 * - counters: next nonce counter per outgoing transfer. Not secret. Reserved
 *   in one readwrite transaction, so two tabs never get the same counter.
 * - packets: outgoing encrypted chunks, saved BEFORE they are sent, so a
 *   retry sends the same bytes (plan 5.3).
 * - chunks: incoming chunks, stored as received (still under the file key)
 *   and only after AES-GCM verified them.
 *
 * Packets and chunks are ciphertext under the per-file key, so they are not
 * sealed a second time.
 */
import { fromBase64url, lp, toBase64url, utf8, fromUtf8 } from "../crypto/encoding";
import { bitmapBytes, type FileManifestV1 } from "../crypto/fileManifest";
import { done, open, openDb, req, seal, type Sealed } from "../crypto/session-store";

const RECORD_LABEL = "krypt-file-transfer-v1";

export type TransferStatus = "offered" | "sending" | "paused" | "receiving" | "complete" | "cancelled" | "expired";

export interface TransferRecord {
  manifest: FileManifestV1;
  direction: "out" | "in";
  peer: string;
  status: TransferStatus;
  /** out: chunks the peer acknowledged; in: chunks verified and stored. */
  have: Uint8Array;
  /** in only: nonce counters already accepted, so a reused counter is refused. */
  usedCounters: number[];
  /** Shown to the user when a transfer stops for a reason other than cancel. */
  note?: string;
  createdAt: number;
  updatedAt: number;
}

export interface ChunkPacket {
  nonceCounter: number;
  /** ciphertext ‖ tag */
  data: Uint8Array;
}

interface RecordJson extends Omit<TransferRecord, "have"> {
  have: string;
}

export const emptyBitmap = (chunkCount: number) => new Uint8Array(bitmapBytes(chunkCount));
export const hasBit = (b: Uint8Array, i: number) => ((b[i >> 3] ?? 0) & (1 << (i & 7))) !== 0;
export const setBit = (b: Uint8Array, i: number) => {
  b[i >> 3] |= 1 << (i & 7);
};
export const countBits = (b: Uint8Array, n: number) => {
  let c = 0;
  for (let i = 0; i < n; i++) if (hasBit(b, i)) c++;
  return c;
};

const chunkKey = (id: string, index: number) => `${id}:${index.toString().padStart(4, "0")}`;
const allOf = (id: string) => IDBKeyRange.bound(`${id}:`, `${id}:￿`);

export interface FileStoreOptions {
  key: CryptoKey;
  dbName: string;
  indexedDB?: IDBFactory;
}

export class FileStore {
  private db: Promise<IDBDatabase>;
  private key: CryptoKey;

  constructor(opts: FileStoreOptions) {
    this.key = opts.key;
    this.db = openDb(opts.indexedDB ?? globalThis.indexedDB, opts.dbName, ["transfers", "counters", "packets", "chunks"]);
  }

  private async sealRecord(rec: TransferRecord): Promise<Sealed> {
    const j: RecordJson = { ...rec, have: toBase64url(rec.have) };
    return seal(this.key, lp(RECORD_LABEL, rec.manifest.transferId), utf8(JSON.stringify(j)));
  }

  private async openRecord(id: string, sealed: Sealed): Promise<TransferRecord> {
    const j = JSON.parse(fromUtf8(await open(this.key, lp(RECORD_LABEL, id), sealed))) as RecordJson;
    return { ...j, have: fromBase64url(j.have) };
  }

  async getTransfer(id: string): Promise<TransferRecord | undefined> {
    const sealed = await req<Sealed | undefined>((await this.db).transaction("transfers").objectStore("transfers").get(id));
    return sealed ? this.openRecord(id, sealed) : undefined;
  }

  async listTransfers(): Promise<TransferRecord[]> {
    const store = (await this.db).transaction("transfers").objectStore("transfers");
    const [keys, values] = await Promise.all([req(store.getAllKeys()), req<Sealed[]>(store.getAll())]);
    return Promise.all(values.map((v, i) => this.openRecord(String(keys[i]), v)));
  }

  async putTransfer(rec: TransferRecord): Promise<void> {
    const sealed = await this.sealRecord(rec);
    const tx = (await this.db).transaction("transfers", "readwrite");
    tx.objectStore("transfers").put(sealed, rec.manifest.transferId);
    await done(tx);
  }

  /** Returns the next nonce counter for `id` and persists counter + 1, in one transaction. */
  async reserveCounter(id: string): Promise<number> {
    const tx = (await this.db).transaction("counters", "readwrite");
    const store = tx.objectStore("counters");
    let reserved = 0;
    const r = store.get(id);
    r.onsuccess = () => {
      reserved = (r.result as number | undefined) ?? 0;
      store.put(reserved + 1, id);
    };
    await done(tx);
    return reserved;
  }

  async putPacket(id: string, index: number, p: ChunkPacket): Promise<void> {
    const tx = (await this.db).transaction("packets", "readwrite");
    tx.objectStore("packets").put(p, chunkKey(id, index));
    await done(tx);
  }

  async getPacket(id: string, index: number): Promise<ChunkPacket | undefined> {
    return req((await this.db).transaction("packets").objectStore("packets").get(chunkKey(id, index)));
  }

  async deletePackets(id: string, indices: number[]): Promise<void> {
    if (indices.length === 0) return;
    const tx = (await this.db).transaction("packets", "readwrite");
    for (const i of indices) tx.objectStore("packets").delete(chunkKey(id, i));
    await done(tx);
  }

  /** Stores a verified incoming chunk and the updated record atomically. */
  async putChunk(rec: TransferRecord, index: number, p: ChunkPacket): Promise<void> {
    const sealed = await this.sealRecord(rec);
    const tx = (await this.db).transaction(["chunks", "transfers"], "readwrite");
    tx.objectStore("chunks").put(p, chunkKey(rec.manifest.transferId, index));
    tx.objectStore("transfers").put(sealed, rec.manifest.transferId);
    await done(tx);
  }

  async getChunk(id: string, index: number): Promise<ChunkPacket | undefined> {
    return req((await this.db).transaction("chunks").objectStore("chunks").get(chunkKey(id, index)));
  }

  /** Deletes the transfer's packets, chunks and counter; with `record`, the record too. */
  async deleteData(id: string, record = false): Promise<void> {
    const tx = (await this.db).transaction(["packets", "chunks", "counters", "transfers"], "readwrite");
    tx.objectStore("packets").delete(allOf(id));
    tx.objectStore("chunks").delete(allOf(id));
    tx.objectStore("counters").delete(id);
    if (record) tx.objectStore("transfers").delete(id);
    await done(tx);
  }

  /** Number of stored packets and chunks for `id` (tests and cleanup checks). */
  async countData(id: string): Promise<{ packets: number; chunks: number }> {
    const tx = (await this.db).transaction(["packets", "chunks"]);
    const [packets, chunks] = await Promise.all([
      req(tx.objectStore("packets").count(allOf(id))),
      req(tx.objectStore("chunks").count(allOf(id))),
    ]);
    return { packets, chunks };
  }

  async close(): Promise<void> {
    (await this.db).close();
  }
}
