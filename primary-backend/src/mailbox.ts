import type { PrismaClient } from "@prisma/client";

// Offline mailbox: encrypted payloads wait here while the recipient is offline.
// Rules (plan 0.7):
// - flush in createdAt order BEFORE the user is marked online
// - delete exactly the rows that were delivered, never "everything for user X"
// - rows expire after 7 days (purged on flush, at startup and hourly)
// - at most 500 waiting rows AND 50 MB of payload per recipient (a single
//   socket frame may be 16 MB, so the row cap alone allowed ~8 GB)

export const MAILBOX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MAILBOX_QUOTA = 500;
export const MAILBOX_BYTE_QUOTA = 50 * 1024 * 1024;
const FLUSH_BATCH = 100;

export interface QueuedMessage {
  id: string;
  payload: unknown;
}

/** Storage operations the mailbox needs. Prisma in production, a fake in tests. */
export interface MailboxStore {
  /** Rows and payload bytes waiting for `to` that are newer than notBefore. */
  usage(to: string, notBefore: Date): Promise<{ count: number; bytes: number }>;
  insert(row: { to: string; from: string; payload: unknown; bytes: number }): Promise<void>;
  /** Oldest first (createdAt, then id), only rows newer than notBefore. */
  fetch(to: string, notBefore: Date, limit: number): Promise<QueuedMessage[]>;
  deleteIds(ids: string[]): Promise<void>;
  purgeExpired(cutoff: Date, to?: string): Promise<number>;
}

export type EnqueueResult = "queued" | "mailbox_full";

/** UTF-8 size of the payload as stored (JSON). */
export function payloadBytes(payload: unknown): number {
  return Buffer.byteLength(JSON.stringify(payload) ?? "", "utf8");
}

export async function enqueue(
  store: MailboxStore,
  row: { to: string; from: string; payload: unknown },
  now = Date.now(),
): Promise<EnqueueResult> {
  const notBefore = new Date(now - MAILBOX_TTL_MS);
  const bytes = payloadBytes(row.payload);
  const waiting = await store.usage(row.to, notBefore);
  if (waiting.count >= MAILBOX_QUOTA || waiting.bytes + bytes > MAILBOX_BYTE_QUOTA) {
    return "mailbox_full";
  }
  await store.insert({ ...row, bytes });
  return "queued";
}

/**
 * Deliver every waiting message for `to`, oldest first.
 * `deliver` returns false when the socket is gone; flushing stops and only the
 * rows already handed over are deleted. Returns the number delivered.
 */
export async function flush(
  store: MailboxStore,
  to: string,
  deliver: (payload: unknown) => boolean,
  now = Date.now(),
): Promise<number> {
  const cutoff = new Date(now - MAILBOX_TTL_MS);
  await store.purgeExpired(cutoff, to);

  let total = 0;
  for (;;) {
    const batch = await store.fetch(to, cutoff, FLUSH_BATCH);
    if (batch.length === 0) return total;

    const delivered: string[] = [];
    let stopped = false;
    for (const msg of batch) {
      if (!deliver(msg.payload)) {
        stopped = true;
        break;
      }
      delivered.push(msg.id);
    }
    if (delivered.length > 0) await store.deleteIds(delivered);
    total += delivered.length;
    if (stopped || batch.length < FLUSH_BATCH) return total;
  }
}

export function prismaMailboxStore(prisma: PrismaClient): MailboxStore {
  return {
    usage: async (to, notBefore) => {
      const r = await prisma.offlineMessage.aggregate({
        where: { to, createdAt: { gte: notBefore } },
        _count: { _all: true },
        _sum: { bytes: true },
      });
      return { count: r._count._all, bytes: r._sum.bytes ?? 0 };
    },
    insert: async ({ to, from, payload, bytes }) => {
      await prisma.offlineMessage.create({ data: { to, from, payload: payload as object, bytes } });
    },
    fetch: (to, notBefore, limit) =>
      prisma.offlineMessage.findMany({
        where: { to, createdAt: { gte: notBefore } },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        select: { id: true, payload: true },
        take: limit,
      }),
    deleteIds: async (ids) => {
      await prisma.offlineMessage.deleteMany({ where: { id: { in: ids } } });
    },
    purgeExpired: async (cutoff, to) => {
      const { count } = await prisma.offlineMessage.deleteMany({
        where: { createdAt: { lt: cutoff }, ...(to ? { to } : {}) },
      });
      return count;
    },
  };
}
