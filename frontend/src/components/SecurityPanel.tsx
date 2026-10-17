import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import toast from "react-hot-toast";
import { safetyNumber } from "../crypto/safetyNumber";
import type { SessionStatus } from "../crypto/session";
import { getKtPeerState, getKtState, ktVersion, subscribeKt } from "../services/kt";
import type { Protocol } from "../services/protocol";
import { loadContact, pinnedDsa, type ContactRecord } from "../services/trust";
import { ktPeerSummary, ktSummary, toneClass } from "./ktSummary";

interface Props {
  peer: string;
  protocol: Protocol;
  onClose: () => void;
}

interface Loaded {
  contact: ContactRecord | null;
  safety: string[] | null;
  status: SessionStatus | null;
}

const suiteLabel = (s: string) => (s === "mlkem1024" ? "ML-KEM-1024" : s);

/**
 * Per-contact security screen (plan 3.4): safety number, key transparency
 * status, session status, and the history of accepted key changes.
 */
export default function SecurityPanel({ peer, protocol, onClose }: Props) {
  const [data, setData] = useState<Loaded | null>(null);
  const [checking, setChecking] = useState(false);
  useSyncExternalStore(subscribeKt, ktVersion);
  const ktPeer = ktPeerSummary(getKtPeerState(peer));
  const ktGlobal = ktSummary(getKtState());

  const load = useCallback(async () => {
    let contact: ContactRecord | null = null;
    try {
      contact = await loadContact(peer, protocol.keys);
    } catch {
      contact = null;
    }
    const theirs = contact ? pinnedDsa(contact) : null;
    const safety = theirs ? await safetyNumber(protocol.keys.dsaPublicKey, theirs) : null;
    const status = await protocol.session.getStatus(peer);
    return { contact, safety, status };
  }, [peer, protocol]);

  useEffect(() => {
    let live = true;
    load().then((d) => {
      if (live) setData(d);
    });
    return () => {
      live = false;
    };
  }, [load]);

  const recheck = async () => {
    const theirs = data?.contact ? pinnedDsa(data.contact) : null;
    if (!theirs) return;
    setChecking(true);
    try {
      await protocol.kt.verifyPeer(peer, theirs);
    } finally {
      setChecking(false);
    }
  };

  const resetSession = async () => {
    if (!window.confirm(`Close the current session with ${peer}? The next message starts a new handshake.`)) return;
    await protocol.session.closeSession(peer);
    toast.success(`Session with ${peer} closed.`);
    setData(await load());
  };

  const s = data?.status;
  return (
    <div className="fixed inset-0 z-40 bg-black/70 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="security-title">
      <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 space-y-5">
        <div className="flex justify-between items-center">
          <h2 id="security-title" className="text-lg font-bold text-slate-100">
            Security: {peer}
          </h2>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-slate-200" aria-label="Close">
            ✕
          </button>
        </div>

        <section>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Safety number</h3>
          {!data ? (
            <p className="text-sm text-slate-500">Loading…</p>
          ) : data.safety ? (
            <>
              <div className="grid grid-cols-4 gap-2 font-mono text-lg text-slate-100 bg-slate-950 border border-slate-800 rounded-xl p-4" data-testid="safety-number">
                {data.safety.map((g, i) => (
                  <span key={i} className="text-center">
                    {g}
                  </span>
                ))}
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Compare these 60 digits with {peer} in person or on a call. They are the SHA-256 of both ML-DSA-87
                identity keys and are the same on both devices. If they differ, someone is in the middle.
              </p>
            </>
          ) : (
            <p className="text-sm text-slate-400">No identity key pinned for {peer} yet. Exchange a message first.</p>
          )}
        </section>

        <section>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Key transparency</h3>
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`px-2 py-0.5 rounded-full border text-xs font-bold ${toneClass[ktPeer.tone]}`} data-testid="kt-peer-status">
              {ktPeer.label}
            </span>
            <span className={`px-2 py-0.5 rounded-full border text-[10px] font-bold uppercase ${toneClass[ktGlobal.tone]}`}>{ktGlobal.label}</span>
            {protocol.kt.enabled && data?.contact && (
              <button
                type="button"
                onClick={recheck}
                disabled={checking}
                className="ml-auto px-3 py-1 text-xs rounded-lg bg-slate-800 border border-slate-700 text-indigo-300 hover:bg-slate-700 disabled:opacity-50"
              >
                {checking ? "Checking…" : "Check now"}
              </button>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-2">{ktPeer.detail}</p>
          {ktGlobal.tone !== "ok" && <p className="text-xs text-slate-500 mt-1">{ktGlobal.detail}</p>}
        </section>

        <section>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Session</h3>
          {!data ? null : s ? (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm" data-testid="session-status">
              <dt className="text-slate-500">Suite</dt>
              <dd className="text-slate-200">{suiteLabel(s.suite)}</dd>
              <dt className="text-slate-500">Epoch</dt>
              <dd className="text-slate-200">
                {s.epoch} <span className="text-slate-500 text-xs">(send {s.sendEpoch}, receive {s.recvEpoch})</span>
              </dd>
              <dt className="text-slate-500">Last ratchet</dt>
              <dd className="text-slate-200">{new Date(s.lastRatchetAt).toLocaleString()}</dd>
              <dt className="text-slate-500">Started</dt>
              <dd className="text-slate-200">
                {new Date(s.createdAt).toLocaleString()} <span className="text-slate-500 text-xs">({s.role})</span>
              </dd>
              <dt className="text-slate-500">Confirmed</dt>
              <dd className="text-slate-200">{s.established ? "yes" : "waiting for a reply"}</dd>
              <dt className="text-slate-500">Session id</dt>
              <dd className="text-slate-400 font-mono text-xs break-all">{s.sessionId.slice(0, 22)}…</dd>
            </dl>
          ) : (
            <p className="text-sm text-slate-400">No session yet. The first message runs the Krypt-X3K handshake.</p>
          )}
          {s && (
            <button
              type="button"
              onClick={resetSession}
              className="mt-3 px-3 py-1 text-xs rounded-lg bg-slate-800 border border-slate-700 text-amber-300 hover:bg-slate-700"
            >
              Reset session
            </button>
          )}
        </section>

        {data?.contact?.keyChanges && data.contact.keyChanges.length > 0 && (
          <section>
            <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider mb-2">Accepted key changes</h3>
            <ul className="text-xs text-slate-300 space-y-1 font-mono">
              {data.contact.keyChanges.map((c, i) => (
                <li key={i}>
                  {new Date(c.at).toLocaleString()}: {c.from} → {c.to}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}
