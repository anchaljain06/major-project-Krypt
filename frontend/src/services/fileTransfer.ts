/**
 * Large-file transfer orchestration (spec 15, plan sections 5-7 and 10).
 *
 * Control messages (offer, accept, reject, ack, resume, complete, cancel) go
 * through the normal SessionManager path (`sendControl`); chunks go as binary
 * `file:chunk` frames (`sendChunk`). This class owns transfer state, nonce
 * allocation and acknowledgements; it never touches ratchet state.
 *
 * Sender, per chunk: reserve a nonce counter (persisted) -> read one slice of
 * the file -> AES-GCM -> save the packet -> send it. At most WINDOW chunks are
 * sent and not yet acknowledged. A retry resends the saved packet unchanged;
 * a chunk with no saved packet gets a fresh counter.
 *
 * Receiver, per chunk: check the transfer, index, length and counter ->
 * decrypt with the canonical AAD -> store chunk + bitmap in one transaction
 * -> acknowledge (batched). Plaintext is released only by `download`, after
 * every chunk is present, and each chunk is authenticated again on the way.
 *
 * Delivery is online only. If the relay answers OFFLINE (or the send fails)
 * the sender pauses; the receiver sends `resume` with its bitmap when it
 * reconnects or sees the sender come online, and only missing chunks follow.
 */
import { fromBase64url, toBase64url } from "../crypto/encoding";
import {
  GCM_TAG_BYTES,
  MAX_FILE_BYTES,
  chunkAad,
  chunkLength,
  chunkNonce,
  createManifest,
  isNonceCounter,
  isTransferId,
  safeFileName,
  type FileControl,
  type FileManifestV1,
} from "../crypto/fileManifest";
import { decryptFileChunk, encryptFileChunk, importFileKey } from "../crypto/fileTransfer";
import type { LockFn } from "../crypto/session";
import {
  countBits,
  emptyBitmap,
  hasBit,
  setBit,
  type ChunkPacket,
  type FileStore,
  type TransferRecord,
  type TransferStatus,
} from "./fileStore";

/** Chunks sent and not yet acknowledged, per transfer (bounds memory and stored packets). */
export const WINDOW = 8;
/** The receiver acknowledges after this many new chunks, or ACK_DELAY_MS after the first unacknowledged one. */
export const ACK_EVERY = 4;
export const ACK_DELAY_MS = 500;
/** Offered, sending or receiving transfers per direction. */
export const MAX_ACTIVE_TRANSFERS = 4;
/** Incoming file bytes this device keeps (active and completed, until they expire). */
export const MAX_STORED_BYTES = 512 * 1024 * 1024;
/** A transfer with no activity for this long is stopped and its data deleted. */
export const TRANSFER_TTL_MS = 24 * 60 * 60 * 1000;

export type ChunkSendResult = "ok" | string;

export interface ChunkFrame {
  transferId: string;
  index: number;
  nonceCounter: number;
  data: Uint8Array;
}

export interface FileTransferDeps {
  self: string;
  store: FileStore;
  lock: LockFn;
  sendControl(peer: string, ctl: FileControl): Promise<void>;
  /** Relays one chunk; resolves "ok" or the relay's error code. */
  sendChunk(peer: string, frame: ChunkFrame): Promise<ChunkSendResult>;
  now?: () => number;
  ackDelayMs?: number;
}

export interface TransferView {
  transferId: string;
  direction: "out" | "in";
  peer: string;
  name: string;
  size: number;
  status: TransferStatus;
  done: number;
  chunkCount: number;
  note?: string;
}

const ACTIVE: TransferStatus[] = ["offered", "sending", "paused", "receiving"];
const TERMINAL: TransferStatus[] = ["complete", "cancelled", "expired"];
/** Relay answers that a later `resume` can fix; anything else stops the transfer. */
const RETRYABLE = new Set(["OFFLINE", "RATE_LIMITED", "TOO_MANY_TRANSFERS", "SERVER_ERROR", "NO_ACK"]);

export class FileTransferError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FileTransferError";
  }
}

function view(r: TransferRecord): TransferView {
  return {
    transferId: r.manifest.transferId,
    direction: r.direction,
    peer: r.peer,
    name: r.manifest.name,
    size: r.manifest.size,
    status: r.status,
    done: countBits(r.have, r.manifest.chunkCount),
    chunkCount: r.manifest.chunkCount,
    ...(r.note ? { note: r.note } : {}),
  };
}

export class FileTransferManager {
  private readonly d: FileTransferDeps;
  private readonly now: () => number;
  private readonly views = new Map<string, TransferView>();
  private readonly listeners = new Set<() => void>();
  private readonly files = new Map<string, Blob>();
  private readonly keys = new Map<string, Promise<CryptoKey>>();
  /** Outgoing: chunks sent in this page's lifetime and not yet acknowledged. */
  private readonly inFlight = new Map<string, Set<number>>();
  private readonly pumping = new Set<string>();
  private readonly pumpAgain = new Set<string>();
  /** Incoming: new chunks since the last ack, and the pending ack timer. */
  private readonly unacked = new Map<string, number>();
  private readonly ackTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private ready: Promise<void>;

  constructor(deps: FileTransferDeps) {
    this.d = deps;
    this.now = deps.now ?? Date.now;
    this.ready = this.load();
  }

  // -------------------------------------------------------------------------
  // State

  /** Loads records, expires stale ones, and pauses sends whose page was closed. */
  private async load(): Promise<void> {
    for (const r of await this.d.store.listTransfers()) {
      if (r.direction === "out" && r.status === "sending") {
        r.status = "paused";
        await this.d.store.putTransfer(r);
      }
      this.views.set(r.manifest.transferId, view(r));
    }
    await this.expire();
  }

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  get(id: string): TransferView | undefined {
    return this.views.get(id);
  }

  list(): TransferView[] {
    return [...this.views.values()];
  }

  whenReady(): Promise<void> {
    return this.ready;
  }

  private publish(r: TransferRecord) {
    this.views.set(r.manifest.transferId, view(r));
    this.listeners.forEach((fn) => fn());
  }

  private locked<T>(id: string, fn: () => Promise<T>): Promise<T> {
    return this.d.lock(`krypt-file:${this.d.self}:${id}`, fn);
  }

  /** Read-modify-write of one record under its lock; `fn` returns false to skip the write. */
  private update(id: string, fn: (r: TransferRecord) => boolean | Promise<boolean>): Promise<TransferRecord | undefined> {
    return this.locked(id, async () => {
      const r = await this.d.store.getTransfer(id);
      if (!r || !(await fn(r))) return undefined;
      r.updatedAt = this.now();
      await this.d.store.putTransfer(r);
      this.publish(r);
      return r;
    });
  }

  private key(m: FileManifestV1): Promise<CryptoKey> {
    let k = this.keys.get(m.transferId);
    if (!k) {
      k = importFileKey(m.fileKey);
      this.keys.set(m.transferId, k);
    }
    return k;
  }

  /** Stops an active transfer for good: sets the status, then deletes its packets, chunks and counter. */
  private async finish(id: string, status: "complete" | "cancelled" | "expired", note?: string) {
    const r = await this.update(id, (x) => {
      if (TERMINAL.includes(x.status)) return false;
      x.status = status;
      if (note) x.note = note;
      return true;
    });
    if (!r) return;
    this.files.delete(id);
    this.inFlight.delete(id);
    this.clearAckTimer(id);
    await this.d.store.deleteData(id);
  }

  /** Expires transfers idle for TRANSFER_TTL_MS; deletes finished ones entirely. */
  async expire(): Promise<void> {
    const cutoff = this.now() - TRANSFER_TTL_MS;
    for (const r of await this.d.store.listTransfers()) {
      if (r.updatedAt > cutoff) continue;
      const id = r.manifest.transferId;
      if (TERMINAL.includes(r.status)) {
        await this.d.store.deleteData(id, true);
        this.views.delete(id);
        this.keys.delete(id);
        this.listeners.forEach((fn) => fn());
      } else {
        await this.finish(id, r.direction === "in" ? "expired" : "cancelled", "Expired after a day without progress.");
      }
    }
  }

  private async activeCount(direction: "out" | "in"): Promise<TransferRecord[]> {
    return (await this.d.store.listTransfers()).filter((r) => r.direction === direction && ACTIVE.includes(r.status));
  }

  // -------------------------------------------------------------------------
  // Sender

  /** Offers `file` to `peer`. Chunks flow after the peer accepts. */
  async offer(peer: string, file: Blob, name: string, mime = file.type): Promise<FileManifestV1> {
    await this.ready;
    if (file.size > MAX_FILE_BYTES) {
      throw new FileTransferError(`File is too large: limit ${Math.round(MAX_FILE_BYTES / (1024 * 1024))} MB.`);
    }
    if ((await this.activeCount("out")).length >= MAX_ACTIVE_TRANSFERS) {
      throw new FileTransferError(`At most ${MAX_ACTIVE_TRANSFERS} outgoing transfers at a time.`);
    }
    const manifest = createManifest(name, mime, file.size);
    const t = this.now();
    const r: TransferRecord = {
      manifest,
      direction: "out",
      peer,
      status: "offered",
      have: emptyBitmap(manifest.chunkCount),
      usedCounters: [],
      createdAt: t,
      updatedAt: t,
    };
    await this.d.store.putTransfer(r);
    this.files.set(manifest.transferId, file);
    this.publish(r);
    try {
      await this.d.sendControl(peer, { op: "offer", manifest });
    } catch (err) {
      await this.finish(manifest.transferId, "cancelled", "The offer could not be sent.");
      throw err;
    }
    return manifest;
  }

  /** Encrypts chunk `index` under a freshly reserved counter and saves the packet. Null if the file is gone. */
  private async sealChunk(r: TransferRecord, index: number): Promise<ChunkPacket | null> {
    const id = r.manifest.transferId;
    const file = this.files.get(id);
    if (!file) return null;
    const nonceCounter = await this.d.store.reserveCounter(id);
    const start = index * r.manifest.chunkSize;
    const plaintext = new Uint8Array(await file.slice(start, start + chunkLength(r.manifest, index)).arrayBuffer());
    const data = await encryptFileChunk({
      fileKey: await this.key(r.manifest),
      nonce: chunkNonce(r.manifest, nonceCounter),
      plaintext,
      aad: chunkAad(r.manifest, this.d.self, r.peer, index, nonceCounter),
    });
    plaintext.fill(0);
    const packet = { nonceCounter, data };
    await this.d.store.putPacket(id, index, packet);
    return packet;
  }

  /** Starts sending without making the caller (the receive queue) wait for it. */
  private kick(id: string) {
    this.pump(id).catch((err) => console.error("[Krypt] file send:", err));
  }

  /** Sends what the window allows. Single-flight per transfer; a call during a run schedules one more run. */
  private async pump(id: string): Promise<void> {
    if (this.pumping.has(id)) {
      this.pumpAgain.add(id);
      return;
    }
    this.pumping.add(id);
    try {
      do {
        this.pumpAgain.delete(id);
        await this.pumpOnce(id);
      } while (this.pumpAgain.has(id));
    } finally {
      this.pumping.delete(id);
    }
  }

  private async pumpOnce(id: string): Promise<void> {
    const sent = this.inFlight.get(id) ?? new Set<number>();
    this.inFlight.set(id, sent);
    for (;;) {
      const r = await this.d.store.getTransfer(id);
      if (!r || r.direction !== "out" || r.status !== "sending") return;
      let index = -1;
      for (let i = 0; i < r.manifest.chunkCount; i++) {
        if (!hasBit(r.have, i) && !sent.has(i)) {
          index = i;
          break;
        }
      }
      if (index < 0 || sent.size >= WINDOW) return;
      const packet = (await this.d.store.getPacket(id, index)) ?? (await this.sealChunk(r, index));
      if (!packet) {
        await this.finish(id, "cancelled", "The file is no longer open on this device. Send it again.");
        await this.d.sendControl(r.peer, { op: "cancel", transferId: id }).catch(() => {});
        return;
      }
      let result: ChunkSendResult;
      try {
        result = await this.d.sendChunk(r.peer, { transferId: id, index, nonceCounter: packet.nonceCounter, data: packet.data });
      } catch {
        result = "NO_ACK";
      }
      if (result !== "ok") {
        if (RETRYABLE.has(result)) {
          await this.update(id, (x) => {
            if (x.status !== "sending") return false;
            x.status = "paused";
            x.note = `Waiting for ${x.peer} to come back online.`;
            return true;
          });
        } else {
          await this.finish(id, "cancelled", `The relay refused the file (${result}).`);
          await this.d.sendControl(r.peer, { op: "cancel", transferId: id }).catch(() => {});
        }
        return;
      }
      sent.add(index);
    }
  }

  /** The peer's bitmap of verified chunks: drop their packets and send more. `resume` also re-sends anything in flight. */
  private async onHave(peer: string, id: string, haveB64: string, resume: boolean) {
    const have = fromBase64url(haveB64);
    let acked: number[] = [];
    const r = await this.update(id, (x) => {
      if (x.direction !== "out" || x.peer !== peer) return false;
      if (x.status !== "sending" && !(resume && x.status === "paused")) return false;
      if (have.length !== x.have.length) return false;
      acked = [];
      for (let i = 0; i < x.manifest.chunkCount; i++) {
        if (hasBit(have, i) && !hasBit(x.have, i)) {
          setBit(x.have, i);
          acked.push(i);
        }
      }
      if (resume) {
        x.status = "sending";
        delete x.note;
      }
      return true;
    });
    if (!r) return;
    const sent = this.inFlight.get(id);
    if (resume) this.inFlight.set(id, new Set());
    else acked.forEach((i) => sent?.delete(i));
    await this.d.store.deletePackets(id, acked);
    this.kick(id);
  }

  // -------------------------------------------------------------------------
  // Receiver

  async accept(id: string): Promise<void> {
    await this.ready;
    const r = await this.update(id, (x) => {
      if (x.direction !== "in" || x.status !== "offered") return false;
      x.status = "receiving";
      return true;
    });
    if (r) await this.d.sendControl(r.peer, { op: "accept", transferId: id });
  }

  async reject(id: string): Promise<void> {
    await this.ready;
    const r = this.views.get(id);
    if (!r || r.direction !== "in" || r.status !== "offered") return;
    await this.finish(id, "cancelled", "You declined this file.");
    await this.d.sendControl(r.peer, { op: "reject", transferId: id });
  }

  private async onOffer(peer: string, m: FileManifestV1): Promise<boolean> {
    if (this.views.has(m.transferId) || (await this.d.store.getTransfer(m.transferId))) return false;
    await this.expire();
    const records = await this.d.store.listTransfers();
    const active = records.filter((r) => r.direction === "in" && ACTIVE.includes(r.status));
    const stored = records
      .filter((r) => r.direction === "in" && r.status !== "cancelled" && r.status !== "expired")
      .reduce((n, r) => n + r.manifest.size, 0);
    const t = this.now();
    const r: TransferRecord = {
      manifest: m,
      direction: "in",
      peer,
      status: "offered",
      have: emptyBitmap(m.chunkCount),
      usedCounters: [],
      createdAt: t,
      updatedAt: t,
    };
    const full =
      active.length >= MAX_ACTIVE_TRANSFERS
        ? `Declined automatically: ${MAX_ACTIVE_TRANSFERS} transfers are already open.`
        : stored + m.size > MAX_STORED_BYTES
          ? "Declined automatically: not enough file storage left on this device."
          : null;
    if (full) {
      r.status = "cancelled";
      r.note = full;
    }
    await this.d.store.putTransfer(r);
    this.publish(r);
    if (full) await this.d.sendControl(peer, { op: "reject", transferId: m.transferId }).catch(() => {});
    return true;
  }

  /** One relayed `file:chunk` frame. Anything that does not verify is dropped silently. */
  async onChunk(from: string, raw: unknown): Promise<void> {
    await this.ready;
    const f = raw as { transferId?: unknown; index?: unknown; nonceCounter?: unknown; data?: unknown } | null;
    if (!f || typeof f !== "object" || !isTransferId(f.transferId) || !isNonceCounter(f.nonceCounter)) return;
    if (typeof f.index !== "number" || !Number.isSafeInteger(f.index) || f.index < 0) return;
    // socket.io delivers binary as an ArrayBuffer in the browser.
    const data =
      f.data instanceof Uint8Array ? f.data : f.data instanceof ArrayBuffer ? new Uint8Array(f.data) : null;
    if (!data) return;
    const id = f.transferId;
    const index = f.index;
    const nonceCounter = f.nonceCounter;

    let status: "stored" | "duplicate" | "complete" | null = null;
    await this.locked(id, async () => {
      const r = await this.d.store.getTransfer(id);
      if (!r || r.direction !== "in" || r.peer !== from || r.status !== "receiving") return;
      if (index >= r.manifest.chunkCount) return;
      if (data.length !== chunkLength(r.manifest, index) + GCM_TAG_BYTES) return;
      if (hasBit(r.have, index)) {
        status = "duplicate";
        return;
      }
      if (r.usedCounters.includes(nonceCounter)) return;
      try {
        await decryptFileChunk({
          fileKey: await this.key(r.manifest),
          nonce: chunkNonce(r.manifest, nonceCounter),
          ciphertextAndTag: data,
          aad: chunkAad(r.manifest, from, this.d.self, index, nonceCounter),
        });
      } catch {
        console.warn(`[Krypt] file chunk ${index} from ${from} failed authentication; dropped.`);
        return;
      }
      setBit(r.have, index);
      r.usedCounters.push(nonceCounter);
      r.updatedAt = this.now();
      const complete = countBits(r.have, r.manifest.chunkCount) === r.manifest.chunkCount;
      if (complete) r.status = "complete";
      await this.d.store.putChunk(r, index, { nonceCounter, data });
      this.publish(r);
      status = complete ? "complete" : "stored";
    });

    if (status === "complete") {
      this.clearAckTimer(id);
      await this.sendHave(id, "ack");
      await this.d.sendControl(from, { op: "complete", transferId: id });
    } else if (status) {
      this.scheduleAck(id, status === "duplicate");
    }
  }

  private clearAckTimer(id: string) {
    const t = this.ackTimers.get(id);
    if (t) clearTimeout(t);
    this.ackTimers.delete(id);
    this.unacked.delete(id);
  }

  private scheduleAck(id: string, now: boolean) {
    const n = (this.unacked.get(id) ?? 0) + 1;
    this.unacked.set(id, n);
    if (now || n >= ACK_EVERY) {
      this.clearAckTimer(id);
      void this.sendHave(id, "ack");
    } else if (!this.ackTimers.has(id)) {
      this.ackTimers.set(
        id,
        setTimeout(() => {
          this.clearAckTimer(id);
          void this.sendHave(id, "ack");
        }, this.d.ackDelayMs ?? ACK_DELAY_MS),
      );
    }
  }

  private async sendHave(id: string, op: "ack" | "resume"): Promise<void> {
    const r = await this.d.store.getTransfer(id);
    if (!r || r.direction !== "in") return;
    await this.d.sendControl(r.peer, { op, transferId: id, have: toBase64url(r.have) }).catch((err) => {
      console.warn(`[Krypt] file ${op} to ${r.peer} failed:`, err);
    });
  }

  /** Asks senders to continue: call after reconnecting, or when `peer` comes online. */
  async resumeWith(peer?: string): Promise<void> {
    await this.ready;
    for (const r of await this.d.store.listTransfers()) {
      if (r.direction === "in" && r.status === "receiving" && (!peer || r.peer === peer)) {
        await this.sendHave(r.manifest.transferId, "resume");
      }
    }
  }

  /** The verified file as a Blob (never rendered: type is octet-stream) and a safe filename. */
  async download(id: string): Promise<{ blob: Blob; name: string }> {
    await this.ready;
    const r = await this.d.store.getTransfer(id);
    if (!r || r.direction !== "in" || r.status !== "complete") throw new FileTransferError("This file is not available.");
    const key = await this.key(r.manifest);
    const parts: Uint8Array<ArrayBuffer>[] = [];
    let total = 0;
    for (let i = 0; i < r.manifest.chunkCount; i++) {
      const c = await this.d.store.getChunk(id, i);
      if (!c) throw new FileTransferError("A part of this file is missing.");
      const pt = await decryptFileChunk({
        fileKey: key,
        nonce: chunkNonce(r.manifest, c.nonceCounter),
        ciphertextAndTag: c.data,
        aad: chunkAad(r.manifest, r.peer, this.d.self, i, c.nonceCounter),
      });
      if (pt.length !== chunkLength(r.manifest, i)) throw new FileTransferError("A part of this file has the wrong size.");
      total += pt.length;
      parts.push(pt as Uint8Array<ArrayBuffer>);
    }
    if (total !== r.manifest.size) throw new FileTransferError("The file has the wrong size.");
    return { blob: new Blob(parts, { type: "application/octet-stream" }), name: safeFileName(r.manifest.name) };
  }

  // -------------------------------------------------------------------------
  // Both sides

  async cancel(id: string): Promise<void> {
    await this.ready;
    const r = this.views.get(id);
    if (!r || TERMINAL.includes(r.status)) return;
    await this.finish(id, "cancelled", "You cancelled this transfer.");
    await this.d.sendControl(r.peer, { op: "cancel", transferId: id }).catch(() => {});
  }

  /**
   * An authenticated control message from `peer`. Returns true for a new
   * offer (the caller shows it in the chat).
   */
  async onControl(peer: string, ctl: FileControl): Promise<boolean> {
    await this.ready;
    if (ctl.op === "offer") return this.onOffer(peer, ctl.manifest);
    const id = ctl.transferId;
    const r = await this.d.store.getTransfer(id);
    if (!r || r.peer !== peer) return false;
    switch (ctl.op) {
      case "accept":
        if (r.direction === "out" && r.status === "offered") {
          await this.update(id, (x) => {
            if (x.status !== "offered") return false;
            x.status = "sending";
            return true;
          });
          this.kick(id);
        }
        break;
      case "reject":
        if (r.direction === "out") await this.finish(id, "cancelled", `${peer} declined the file.`);
        break;
      case "ack":
      case "resume":
        await this.onHave(peer, id, ctl.have, ctl.op === "resume");
        break;
      case "complete":
        if (r.direction === "out") await this.finish(id, "complete");
        break;
      case "cancel":
        await this.finish(id, "cancelled", `${peer} cancelled the transfer.`);
        break;
    }
    return false;
  }
}
