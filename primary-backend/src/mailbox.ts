import type { PrismaClient } from "@prisma/client";

// Offline mailbox: encrypted payloads wait here while the recipient is offline.
// Rules (plan 0.7):
// - flush in createdAt order BEFORE the user is marked online
// - delete exactly the rows that were delivered, never "everything for user X"
// - rows expire after 7 days (purged on flush, at startup and hourly)
// - at most 500 waiting rows per recipient

export const MAILBOX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MAILBOX_QUOTA = 500;
const FLUSH_BATCH = 100;

export interface QueuedMessage {
  id: string;
  payload: unknown;
}

/** Storage operations the mailbox needs. Prisma in production, a fake in tests. */
export interface MailboxStore {
  count(to: string, notBefore: Date): Promise<number>;
  insert(row: { to: string; from: string; payload: unknown }): Promise<void>;
  /** Oldest first (createdAt, then id), only rows newer than notBefore. */
  fetch(to: string, notBefore: Date, limit: number): Promise<QueuedMessage[]>;
  deleteIds(ids: string[]): Promise<void>;
  purgeExpired(cutoff: Date, to?: string): Promise<number>;
}

export type EnqueueResult = "queued" | "mailbox_full";

export async function enqueue(
  store: MailboxStore,
  row: { to: string; from: string; payload: unknown },
  now = Date.now(),
): Promise<EnqueueResult> {
  const notBefore = new Date(now - MAILBOX_TTL_MS);
  const waiting = await store.count(row.to, notBefore);
  if (waiting >= MAILBOX_QUOTA) return "mailbox_full";
  await store.insert(row);
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
    count: (to, notBefore) =>
      prisma.offlineMessage.count({ where: { to, createdAt: { gte: notBefore } } }),
    insert: async ({ to, from, payload }) => {
      await prisma.offlineMessage.create({ data: { to, from, payload: payload as object } });
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
