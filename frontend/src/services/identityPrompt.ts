/**
 * Blocking identity-key-change decisions (plan 3.4).
 *
 * trustIdentity() calls askIdentityChange() and waits; the
 * IdentityChangeDialog component shows the oldest pending request and
 * resolves it. Nothing proceeds for that peer until the user decides.
 */

export interface IdentityChangeRequest {
  id: number;
  peer: string;
  /** Fingerprints (hex groups) of the pinned and the newly presented ML-DSA key. */
  oldFingerprint: string;
  newFingerprint: string;
  /** Key transparency verdict for the new key, shown in the dialog. */
  ktNote: string;
}

interface Pending extends IdentityChangeRequest {
  resolve: (accepted: boolean) => void;
}

let nextId = 1;
let queue: Pending[] = [];
const listeners = new Set<() => void>();

const emit = () => listeners.forEach((l) => l());

export function subscribeIdentityPrompts(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function currentIdentityPrompt(): IdentityChangeRequest | null {
  return queue[0] ?? null;
}

export function askIdentityChange(req: Omit<IdentityChangeRequest, "id">): Promise<boolean> {
  // One open question per peer: later callers share the answer.
  const existing = queue.find((p) => p.peer === req.peer && p.newFingerprint === req.newFingerprint);
  if (existing) {
    return new Promise((resolve) => {
      const prev = existing.resolve;
      existing.resolve = (a) => {
        prev(a);
        resolve(a);
      };
    });
  }
  return new Promise((resolve) => {
    queue = [...queue, { ...req, id: nextId++, resolve }];
    emit();
  });
}

export function answerIdentityPrompt(id: number, accepted: boolean) {
  const p = queue.find((q) => q.id === id);
  if (!p) return;
  queue = queue.filter((q) => q.id !== id);
  emit();
  p.resolve(accepted);
}
