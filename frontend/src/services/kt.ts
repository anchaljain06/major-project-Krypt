/**
 * Key transparency client (plan 3.1-3.3), built on shared/ (imported as
 * `@krypt/shared`, see vite.config.ts).
 *
 * Trust anchors are compiled in, never fetched:
 *   VITE_KT_LOG_PUBKEY       base64 ML-DSA-87 public key of the log's tree heads.
 *                            Unset -> KT runs in "disabled" mode (TOFU only) and
 *                            the UI shows a warning badge.
 *   VITE_KT_WITNESS_URL      optional: the witness's latest.json (GitHub Pages).
 *   VITE_KT_WITNESS_PUBKEY   base64 ML-DSA-44 witness key; required to use the URL.
 *
 * What the client checks:
 *   - lookup (before a peer identity is trusted): inclusion proof, STH
 *     signature, leaf owner/key match, owner signature of register leaves,
 *     version not older than the one already seen, and consistency of the STH
 *     with the last STH this device stored (and with the witness head);
 *   - self-monitoring (on login): every leaf appended since the last check is
 *     fetched (paged), authenticated against the signed root, and scanned for
 *     keys under my name that I did not publish;
 *   - gossip: my (treeSize, rootHash) travels inside every encrypted message;
 *     a peer's head that is inconsistent with mine is a fork.
 * Any failed check raises a sticky ALERT.
 *
 * Local state (public data only) is in localStorage `krypt_kt_<user>`.
 */
import {
  CompactRange,
  KtOp,
  attachOwnerSig,
  buildLeafBody,
  checkSthChain,
  cosignatureFromJson,
  encodeLeaf,
  fromBase64,
  hashUsername,
  logIdFromPublicKey,
  ownerSignedMessage,
  parseConsistencyResponse,
  parseLeavesResponse,
  parseLookupResponse,
  selfMonitor,
  sha256,
  sthFromJson,
  sthToJson,
  toBase64,
  verifyCosignature,
  verifyLeafRange,
  verifyLookup,
  verifyTreeHead,
  type CheckResult,
  type KnownKey,
  type LeafEntry,
  type SignedTreeHead,
  type SignedTreeHeadJson,
  type TreeHead,
} from "@krypt/shared";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import type { UserIdentityKeys } from "../crypto/mlkem";
import { mldsaSign, mldsaVerify } from "../crypto/pq";
import { apiFetch, apiPostJson } from "./api";

const API_URL: string = import.meta.env.VITE_API_URL ?? "";

function envKey(name: string): Uint8Array | null {
  const v = (import.meta.env as Record<string, string | undefined>)[name]?.trim();
  if (!v) return null;
  try {
    return fromBase64(v);
  } catch {
    console.error(`[KT] ${name} is not valid base64; ignoring it.`);
    return null;
  }
}

const LOG_PUBKEY = envKey("VITE_KT_LOG_PUBKEY");
const WITNESS_URL = (import.meta.env.VITE_KT_WITNESS_URL as string | undefined)?.trim() || null;
const WITNESS_PUBKEY = envKey("VITE_KT_WITNESS_PUBKEY");
const ML_DSA_87_PK = 2592;
const ML_DSA_44_PK = 1312;
const WITNESS_CACHE_MS = 10 * 60 * 1000;
const WITNESS_STALE_MS = 24 * 60 * 60 * 1000;
const MAX_LEAF_PAGES = 1000;

export const KT_ENABLED = LOG_PUBKEY !== null && LOG_PUBKEY.length === ML_DSA_87_PK;
if (LOG_PUBKEY && !KT_ENABLED) console.error("[KT] VITE_KT_LOG_PUBKEY is not a 2592-byte ML-DSA-87 key; KT disabled.");

// ---------------------------------------------------------------------------
// Observable status (for the badge and the Security panel)

export type KtGlobalState =
  | { mode: "disabled" }
  | { mode: "pending" }
  | { mode: "ok"; treeSize: number; witness: "verified" | "stale" | "none" }
  | { mode: "error"; reason: string }
  | { mode: "alert"; reason: string };

export type KtPeerState =
  | { state: "disabled" }
  | { state: "verified"; keyVersion: number; treeSize: number; at: number }
  | { state: "not-in-log"; at: number }
  | { state: "error"; reason: string; at: number }
  | { state: "alert"; reason: string; at: number };

let globalState: KtGlobalState = KT_ENABLED ? { mode: "pending" } : { mode: "disabled" };
const peerStates = new Map<string, KtPeerState>();
const listeners = new Set<() => void>();
let version = 0;

function emit() {
  version++;
  listeners.forEach((l) => l());
}

export function subscribeKt(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}
export function ktVersion(): number {
  return version;
}
export function getKtState(): KtGlobalState {
  return globalState;
}
export function getKtPeerState(peer: string): KtPeerState {
  if (!KT_ENABLED) return { state: "disabled" };
  return peerStates.get(peer) ?? { state: "error", reason: "not checked yet", at: 0 };
}

function setGlobal(s: KtGlobalState) {
  // An alert is sticky for the page's lifetime.
  if (globalState.mode === "alert" && s.mode !== "alert") return;
  globalState = s;
  emit();
}

// ---------------------------------------------------------------------------
// HTTP

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, path: string) {
    super(`GET ${path}: HTTP ${status}`);
    this.status = status;
  }
}

async function getJson(path: string): Promise<unknown> {
  const res = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!res.ok) throw new HttpError(res.status, path);
  return res.json();
}

// ---------------------------------------------------------------------------
// Persistent state

interface Persisted {
  lastSth: SignedTreeHeadJson | null;
  /** Leaves [0, size) have been self-monitored; root is the signed root at size. */
  monitored: { size: number; root: string } | null;
  peers: Record<string, { keyVersion: number }>;
  alert: string | null;
}

const stateKey = (user: string) => `krypt_kt_${user}`;

function loadPersisted(user: string): Persisted {
  try {
    const p = JSON.parse(localStorage.getItem(stateKey(user)) ?? "null");
    if (p && typeof p === "object") {
      return { lastSth: p.lastSth ?? null, monitored: p.monitored ?? null, peers: p.peers ?? {}, alert: p.alert ?? null };
    }
  } catch {
    // fall through
  }
  return { lastSth: null, monitored: null, peers: {}, alert: null };
}

// ---------------------------------------------------------------------------

const verifySth = (msg: Uint8Array, sig: Uint8Array) => (LOG_PUBKEY ? mldsaVerify(LOG_PUBKEY, msg, sig) : false);
const verifyOwner = (msg: Uint8Array, sig: Uint8Array, pk: Uint8Array) => mldsaVerify(pk, msg, sig);

export class KtClient {
  readonly username: string;
  private readonly keys: UserIdentityKeys;
  private st: Persisted;
  private lastSth: SignedTreeHead | null;
  private myKeyVersion = 1;
  private witnessCheckedAt = 0;
  private witnessResult: "verified" | "stale" | "none" = "none";
  private gossipChecked = new Set<string>();

  constructor(username: string, keys: UserIdentityKeys) {
    this.username = username;
    this.keys = keys;
    this.st = loadPersisted(username);
    this.lastSth = null;
    try {
      this.lastSth = this.st.lastSth ? sthFromJson(this.st.lastSth) : null;
    } catch {
      this.lastSth = null;
    }
    if (this.st.alert) {
      globalState = { mode: "alert", reason: this.st.alert };
      emit();
    }
  }

  get enabled() {
    return KT_ENABLED;
  }

  private save() {
    try {
      localStorage.setItem(stateKey(this.username), JSON.stringify(this.st));
    } catch {
      // Storage unavailable: checks still run, but state does not persist.
    }
  }

  private raiseAlert(reason: string) {
    console.error(`[KT] ALERT: ${reason}`);
    this.st.alert = reason;
    this.save();
    setGlobal({ mode: "alert", reason });
  }

  /** The head carried as gossip inside encrypted messages. */
  gossip(): { treeSize: number; rootHash: string } | undefined {
    if (!KT_ENABLED || !this.lastSth) return undefined;
    return { treeSize: this.lastSth.treeSize, rootHash: toBase64(this.lastSth.rootHash) };
  }

  /** Consistency between two heads, whichever is larger. */
  private async linkHeads(a: TreeHead, b: TreeHead): Promise<CheckResult> {
    const [small, large] = a.treeSize <= b.treeSize ? [a, b] : [b, a];
    let proof: Uint8Array[] = [];
    if (small.treeSize > 0 && small.treeSize < large.treeSize) {
      const r = parseConsistencyResponse(await getJson(`/kt/consistency?from=${small.treeSize}&to=${large.treeSize}`));
      if (r.from !== small.treeSize || r.to !== large.treeSize) {
        return { ok: false, kind: "inconsistent", reason: "consistency proof is for different sizes" };
      }
      proof = r.proof;
    }
    return checkSthChain(small, large, proof);
  }

  /**
   * Accepts a signature-checked head: it must be consistent with the last head
   * this device stored and with the witness head. The larger one is kept.
   */
  private async acceptSth(sth: SignedTreeHead): Promise<boolean> {
    if (this.lastSth) {
      const link = await this.linkHeads(this.lastSth, sth);
      if (!link.ok) {
        this.raiseAlert(`log ${link.kind}: ${link.reason}`);
        return false;
      }
    }
    if (!(await this.checkWitness(sth))) return false;
    if (!this.lastSth || sth.treeSize > this.lastSth.treeSize) {
      this.lastSth = sth;
      this.st.lastSth = sthToJson(sth);
      this.save();
    }
    setGlobal({ mode: "ok", treeSize: this.lastSth!.treeSize, witness: this.witnessResult });
    return true;
  }

  private async checkWitness(sth: SignedTreeHead): Promise<boolean> {
    if (!WITNESS_URL) return true;
    if (!WITNESS_PUBKEY || WITNESS_PUBKEY.length !== ML_DSA_44_PK) {
      if (this.witnessCheckedAt === 0) console.warn("[KT] VITE_KT_WITNESS_URL is set without a valid VITE_KT_WITNESS_PUBKEY; witness not used.");
      this.witnessCheckedAt = Date.now();
      return true;
    }
    if (Date.now() - this.witnessCheckedAt < WITNESS_CACHE_MS) return true;
    let latest: { sth?: unknown; cosignature?: unknown };
    try {
      const res = await fetch(WITNESS_URL, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      latest = await res.json();
    } catch (err) {
      // An unreachable witness is not evidence of an attack.
      console.warn("[KT] witness unreachable:", err);
      return true;
    }
    try {
      const wSth = sthFromJson(latest.sth);
      const cosig = cosignatureFromJson(latest.cosignature);
      if (!(await verifyTreeHead(wSth, verifySth))) throw new Error("witness head is not signed by the pinned log key");
      const logId = await logIdFromPublicKey(LOG_PUBKEY!);
      const ok = await verifyCosignature(wSth, logId, cosig, (m, s) => ml_dsa44.verify(s, m, WITNESS_PUBKEY));
      if (!ok) throw new Error("witness cosignature does not verify");
      const link = await this.linkHeads(wSth, sth);
      if (!link.ok) {
        this.raiseAlert(`log head disagrees with the witness (${link.kind}): ${link.reason}`);
        return false;
      }
      this.witnessResult = Date.now() - cosig.timestampMs > WITNESS_STALE_MS ? "stale" : "verified";
      this.witnessCheckedAt = Date.now();
      return true;
    } catch (err) {
      console.warn("[KT] witness head rejected:", err);
      return true;
    }
  }

  /** GET /kt/sth, verified and linked to the stored head. */
  async refreshHead(): Promise<SignedTreeHead | null> {
    if (!KT_ENABLED) return null;
    const sth = sthFromJson(await getJson("/kt/sth"));
    if (!(await verifyTreeHead(sth, verifySth))) {
      this.raiseAlert("tree head signature does not verify under the pinned log key");
      return null;
    }
    return (await this.acceptSth(sth)) ? sth : null;
  }

  /** Registers my identity key in the log if it is not there yet (owner-signed register leaf). */
  async registerSelf(): Promise<void> {
    if (!KT_ENABLED) return;
    const res = await apiFetch("/api/kt/status");
    if (!res.ok) throw new Error(`KT status failed (HTTP ${res.status})`);
    const status = (await res.json()) as { hasLeaf?: boolean; keyVersion?: number };
    if (status.hasLeaf) {
      this.myKeyVersion = Number(status.keyVersion) || 1;
      return;
    }
    const body = await buildLeafBody({
      op: KtOp.Register,
      username: this.username,
      keyVersion: 1,
      mldsaPk: this.keys.dsaPublicKey,
      mlkemPk: this.keys.kemPublicKey,
      timestampMs: Date.now(),
    });
    const ownerSig = mldsaSign(this.keys.dsaSecretKey, ownerSignedMessage(body));
    const leaf = await attachOwnerSig(body, ownerSig);
    const post = await apiPostJson("/api/kt/register", { leaf: toBase64(encodeLeaf(leaf)), ownerSig: toBase64(ownerSig) });
    if (!post.ok) {
      const err = await post.json().catch(() => ({}));
      throw new Error(`KT register failed: ${err.error ?? `HTTP ${post.status}`}`);
    }
    this.myKeyVersion = 1;
  }

  /**
   * Owner self-monitoring (plan 3.2): every leaf since the last check, paged,
   * authenticated against the signed root, then scanned for keys under my
   * name that are not mine.
   */
  async monitorSelf(): Promise<void> {
    if (!KT_ENABLED) return;
    const sth = await this.refreshHead();
    if (!sth) return;
    let mon = this.st.monitored;
    if (mon && mon.size > sth.treeSize) mon = null;
    const startSize = mon?.size ?? 0;
    if (startSize === sth.treeSize) return;

    let start: CompactRange | null = startSize === 0 ? CompactRange.empty() : null;
    const entries: LeafEntry[] = [];
    let from = startSize;
    for (let page = 0; from < sth.treeSize; page++) {
      if (page >= MAX_LEAF_PAGES) throw new Error("too many leaf pages");
      const r = parseLeavesResponse(await getJson(`/kt/leaves?from=${from}&to=${sth.treeSize}`));
      if (r.from !== from || r.to <= from || r.to > sth.treeSize) {
        this.raiseAlert(`log served leaves ${r.from}..${r.to} for a request from ${from}`);
        return;
      }
      if (!start) {
        try {
          start = await CompactRange.fromHashes(startSize, r.compactRange, fromBase64(mon!.root));
        } catch {
          this.raiseAlert(`compact range at size ${startSize} does not match the root seen earlier`);
          return;
        }
      }
      entries.push(...r.leaves);
      from = r.to;
    }
    const range = await verifyLeafRange(start!, entries, sth);
    if (!range.ok) {
      this.raiseAlert(`leaf batch rejected: ${range.reason}`);
      return;
    }
    const known: KnownKey[] = [];
    const mldsaPkHash = await sha256(this.keys.dsaPublicKey);
    const mlkemPkHash = await sha256(this.keys.kemPublicKey);
    for (let v = 1; v <= Math.max(1, this.myKeyVersion); v++) known.push({ keyVersion: v, mldsaPkHash, mlkemPkHash });
    const alerts = selfMonitor(await hashUsername(this.username), known, range.leaves);
    if (alerts.length > 0) {
      this.raiseAlert(`self-monitoring: ${alerts.map((a) => a.message).join("; ")}`);
      return;
    }
    this.st.monitored = { size: sth.treeSize, root: toBase64(sth.rootHash) };
    this.save();
  }

  /**
   * Lookup before trusting a peer's identity key (plan 3.1). Returns the
   * peer's KT state; "alert" and "error" mean the key must not be trusted.
   */
  async verifyPeer(peer: string, dsaPub: Uint8Array): Promise<KtPeerState> {
    if (!KT_ENABLED) return { state: "disabled" };
    const at = Date.now();
    const done = (s: KtPeerState) => {
      peerStates.set(peer, s);
      emit();
      return s;
    };
    const pinned = this.st.peers[peer]?.keyVersion;
    let raw: unknown;
    try {
      raw = await getJson(`/kt/proof?user=${encodeURIComponent(peer)}`);
    } catch (err) {
      if (err instanceof HttpError && err.status === 404) {
        if (pinned !== undefined) {
          const reason = `${peer} was in the log (key version ${pinned}) but the log now denies it`;
          this.raiseAlert(reason);
          return done({ state: "alert", reason, at });
        }
        return done({ state: "not-in-log", at });
      }
      return done({ state: "error", reason: `key transparency log unreachable: ${(err as Error).message}`, at });
    }
    let parsed;
    try {
      parsed = parseLookupResponse(raw);
    } catch (err) {
      const reason = `malformed lookup response for ${peer}: ${(err as Error).message}`;
      this.raiseAlert(reason);
      return done({ state: "alert", reason, at });
    }
    const r = await verifyLookup({
      username: peer,
      response: parsed,
      verifySth,
      mldsaPk: dsaPub,
      minKeyVersion: pinned,
      verifySig: verifyOwner,
    });
    if (!r.ok) {
      const reason = `${peer}'s key failed the transparency check: ${r.reason}`;
      this.raiseAlert(reason);
      return done({ state: "alert", reason, at });
    }
    let linked: boolean;
    try {
      linked = await this.acceptSth(r.sth);
    } catch (err) {
      return done({ state: "error", reason: `consistency check failed: ${(err as Error).message}`, at });
    }
    if (!linked) return done({ state: "alert", reason: globalState.mode === "alert" ? globalState.reason : "inconsistent log", at });
    this.st.peers[peer] = { keyVersion: r.leaf.keyVersion };
    this.save();
    return done({ state: "verified", keyVersion: r.leaf.keyVersion, treeSize: r.sth.treeSize, at });
  }

  /** Compares a peer's gossiped head with mine (plan 3.3). */
  async checkGossip(peer: string, g: unknown): Promise<void> {
    if (!KT_ENABLED || !this.lastSth || !g || typeof g !== "object") return;
    const { treeSize, rootHash } = g as { treeSize?: unknown; rootHash?: unknown };
    if (typeof treeSize !== "number" || !Number.isSafeInteger(treeSize) || treeSize < 0 || typeof rootHash !== "string") return;
    const key = `${treeSize}:${rootHash}`;
    if (this.gossipChecked.has(key)) return;
    let root: Uint8Array;
    try {
      root = fromBase64(rootHash);
    } catch {
      return;
    }
    if (root.length !== 32) return;
    try {
      const link = await this.linkHeads({ treeSize, rootHash: root, timestampMs: 0 }, this.lastSth);
      if (!link.ok) {
        this.raiseAlert(`${peer} sees a different log (${link.kind}): ${link.reason}`);
        return;
      }
      this.gossipChecked.add(key);
    } catch (err) {
      // A proof the server will not serve is inconclusive, not proof of a fork.
      console.warn(`[KT] could not check gossip from ${peer}:`, err);
    }
  }
}
