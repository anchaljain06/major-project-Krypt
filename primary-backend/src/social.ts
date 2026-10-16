import { prisma } from "./db.js";

// Relationship checks used to gate message routing.
// Results are cached briefly; REST handlers that change a relationship call
// invalidateRelationship() so the socket layer sees the change at once.

export type MessagePolicy = "ok" | "blocked" | "not_friends";

const CACHE_TTL_MS = 15_000;
const cache = new Map<string, { value: MessagePolicy; expires: number }>();

function pairKey(from: string, to: string) {
  return `${from}\u0000${to}`;
}

export function invalidateRelationship(a: string, b: string) {
  cache.delete(pairKey(a, b));
  cache.delete(pairKey(b, a));
}

export function clearRelationshipCache() {
  cache.clear();
}

/** Can `from` send a private message to `to`? */
export async function messagePolicy(from: string, to: string): Promise<MessagePolicy> {
  const key = pairKey(from, to);
  const hit = cache.get(key);
  if (hit && hit.expires > Date.now()) return hit.value;

  const [block, friendship] = await Promise.all([
    prisma.blockedUser.findFirst({
      where: { blockerUsername: to, blockedUsername: from },
      select: { id: true },
    }),
    prisma.friendRequest.findFirst({
      where: {
        status: "accepted",
        OR: [
          { senderUsername: from, receiverUsername: to },
          { senderUsername: to, receiverUsername: from },
        ],
      },
      select: { id: true },
    }),
  ]);

  const value: MessagePolicy = block ? "blocked" : friendship ? "ok" : "not_friends";
  if (cache.size > 10_000) cache.clear();
  cache.set(key, { value, expires: Date.now() + CACHE_TTL_MS });
  return value;
}
