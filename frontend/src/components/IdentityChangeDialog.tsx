import { useSyncExternalStore } from "react";
import {
  answerIdentityPrompt,
  currentIdentityPrompt,
  subscribeIdentityPrompts,
} from "../services/identityPrompt";

/**
 * Blocking warning shown when a contact presents an identity key different
 * from the one pinned on this device (plan 3.4). Nothing is sent to or
 * accepted from that contact until the user decides; acceptance is recorded
 * in the contact (services/trust.ts).
 */
export default function IdentityChangeDialog() {
  const req = useSyncExternalStore(subscribeIdentityPrompts, currentIdentityPrompt);
  if (!req) return null;
  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="idchange-title"
    >
      <div className="w-full max-w-lg bg-slate-900 border-2 border-red-700 rounded-2xl shadow-2xl p-6 space-y-4">
        <h2 id="idchange-title" className="text-lg font-bold text-red-400">
          {req.peer}'s identity key has changed
        </h2>
        <p className="text-sm text-slate-300">
          The server is presenting a different identity key for <b>{req.peer}</b> than the one this device
          trusted before. This happens when they reset their account or moved to a new vault, but it is also
          exactly what a man-in-the-middle attack looks like. Confirm with {req.peer} through another channel
          (in person or by phone) before accepting.
        </p>
        <div className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1">
          <div>
            <span className="text-slate-500">Trusted key: </span>
            <span className="text-slate-300">{req.oldFingerprint}</span>
          </div>
          <div>
            <span className="text-slate-500">New key:&nbsp;&nbsp;&nbsp;&nbsp; </span>
            <span className="text-amber-300">{req.newFingerprint}</span>
          </div>
        </div>
        <p className="text-xs text-slate-400">{req.ktNote}</p>
        <div className="flex gap-3 justify-end">
          <button
            type="button"
            onClick={() => answerIdentityPrompt(req.id, false)}
            className="px-4 py-2 rounded-lg bg-slate-800 text-slate-200 border border-slate-700 hover:bg-slate-700 text-sm font-semibold"
          >
            Reject new key
          </button>
          <button
            type="button"
            onClick={() => answerIdentityPrompt(req.id, true)}
            className="px-4 py-2 rounded-lg bg-red-700 text-white hover:bg-red-600 text-sm font-semibold"
          >
            I verified it, accept
          </button>
        </div>
      </div>
    </div>
  );
}
