// E7: sparse KEM ratchet interval K, bandwidth vs healing (strategy 4.4 "Sparse mode", spec 5.6 and 9).
//
// Runs in Node (tsx), not in the browser page: it drives the shipped v1 SessionManager from
// frontend/src/crypto/ directly (no copy) with in-memory stores, so the numbers describe the
// real state machine. The test world (directory, parties, rng) is frontend/test/helpers.ts.
//
// For one (suite, K, traffic, seed) cell, runConversation():
//   1. builds Alice and Bob over the in-memory bundle directory of frontend/test/helpers.ts;
//   2. plays a scripted 1,000-message conversation and records, per message, the exact header,
//      body, binary-frame and JSON-frame bytes, whether ratchet data rode on the header, the KEM
//      operations it caused (counted by wrapping the suite objects at runtime) and the
//      encrypt/decrypt wall time with the session-store time measured separately;
//   3. clones Alice's whole store at several compromise points k (the passive attacker Eve).
// analyseSnapshot() then replays the recorded transcript against each snapshot and checks,
// message by message, what Eve can read against the exposure rule of spec section 9.

import {
  Directory,
  makeParty as makeTestParty,
  managerFor,
  rng,
  type Party as TestParty,
} from "../../frontend/test/helpers.ts";
import { mlkem1024, type KemSuite } from "../../frontend/src/crypto/pq.ts";
import type { SessionManager } from "../../frontend/src/crypto/session.ts";
import {
  MemorySessionStore,
  type PeerRecord,
  type SessionState,
  type SessionStore,
} from "../../frontend/src/crypto/session-store.ts";
import {
  encodeBinaryEnvelope,
  headerAad,
  headerBytes,
  parseEnvelope,
  type EnvelopeV1,
} from "../../frontend/src/crypto/envelope.ts";
import { aesGcmDecrypt, kdfChain, messageKeyAndIv } from "../../frontend/src/crypto/kdf.ts";

// ---------------------------------------------------------------------------
// KEM operation counters (runtime wrappers; frontend/ is not modified)

export type KemOp = "keygen" | "encaps" | "decaps";
type Counts = Record<KemOp, number>;
const zero = (): Counts => ({ keygen: 0, encaps: 0, decaps: 0 });
export const kemCounters: Record<"ratchet" | "prekey", Counts> = {
  ratchet: zero(),
  prekey: zero(),
};

// The ratchet and the prekeys both use the one ML-KEM-1024 object, so an
// operation counts as a prekey operation when it uses a registered prekey
// (Alice encapsulating to SPK/OPK, Bob decapsulating with them). Every other
// operation, including all key generation after setup, is a ratchet operation.
const prekeyMaterial = new Set<string>();
const fingerprint = (b: unknown) =>
  b instanceof Uint8Array ? `${b.length}:${Buffer.from(b.subarray(0, 32)).toString("hex")}` : "";

function registerPrekey(r: { publicKey: Uint8Array; secretKey: Uint8Array }): void {
  prekeyMaterial.add(fingerprint(r.publicKey));
  prekeyMaterial.add(fingerprint(r.secretKey));
}

let instrumented = false;
export function instrumentKems(): void {
  if (instrumented) return;
  instrumented = true;
  const k = mlkem1024 as unknown as Record<string, (...a: unknown[]) => unknown>;
  for (const [method, op, keyArg] of [
    ["keygen", "keygen", -1],
    ["encapsulate", "encaps", 0],
    ["decapsulate", "decaps", 1],
  ] as const) {
    const orig = k[method];
    k[method] = (...args: unknown[]) => {
      const prekey = keyArg >= 0 && prekeyMaterial.has(fingerprint(args[keyArg]));
      kemCounters[prekey ? "prekey" : "ratchet"][op]++;
      return orig(...args);
    };
  }
}

function readCounters(): { ratchet: Counts; prekey: Counts } {
  return { ratchet: { ...kemCounters.ratchet }, prekey: { ...kemCounters.prekey } };
}
const diff = (a: Counts, b: Counts): Counts => ({
  keygen: a.keygen - b.keygen,
  encaps: a.encaps - b.encaps,
  decaps: a.decaps - b.decaps,
});
const total = (c: Counts) => c.keygen + c.encaps + c.decaps;

// ---------------------------------------------------------------------------
// World: directory, timed store, parties

/** MemorySessionStore plus a stopwatch, so storage time can be reported apart from crypto time. */
class TimedStore implements SessionStore {
  ms = 0;
  constructor(readonly inner: MemorySessionStore) {}
  async load(peer: string): Promise<PeerRecord | undefined> {
    const t0 = performance.now();
    try {
      return await this.inner.load(peer);
    } finally {
      this.ms += performance.now() - t0;
    }
  }
  async save(peer: string, rec: PeerRecord): Promise<void> {
    const t0 = performance.now();
    try {
      await this.inner.save(peer, rec);
    } finally {
      this.ms += performance.now() - t0;
    }
  }
}

/** A test party whose SessionManager writes through a TimedStore; `store` is the store behind it. */
interface Party extends TestParty {
  timed: TimedStore;
}

interface ManagerOpts {
  suite: KemSuite;
  K: number;
  now: () => number;
}

const partyOpts = (o: ManagerOpts, store?: SessionStore) => ({ suite: o.suite, ratchetEveryK: o.K, now: o.now, store });

/** A second SessionManager over a party's keys and the given store (Eve's stolen copy). */
function manager(p: Party, dir: Directory, store: SessionStore, o: ManagerOpts): SessionManager {
  return managerFor(p, dir, partyOpts(o, store));
}

async function makeParty(dir: Directory, name: "alice" | "bob", o: ManagerOpts): Promise<Party> {
  const timed = new TimedStore(new MemorySessionStore());
  const p = await makeTestParty(dir, name, partyOpts(o, timed));
  const entry = dir.entries.get(name)!;
  registerPrekey((await p.prekeys.getSignedPrekey(entry.signedPrekey.keyId))!);
  for (const k of entry.oneTimePrekeys) registerPrekey((await p.prekeys.getOneTimePrekey(k.keyId))!);
  return { ...p, store: timed.inner, timed };
}

// ---------------------------------------------------------------------------
// Traffic scripts

export type Traffic = "alternate" | "burst5" | "oneSided90" | "poisson";
export const TRAFFIC: readonly Traffic[] = ["alternate", "burst5", "oneSided90", "poisson"];

interface Slot {
  from: "alice" | "bob";
  /** Send time, seconds. */
  t: number;
  /** One-way relay latency, seconds (0 = delivered before the next send). */
  lat: number;
}

/**
 * Message 0 is always Alice's (she initiates) and is delivered at once.
 *  - alternate:  A B A B ...
 *  - burst5:     5 from A, then 5 from B, ...
 *  - oneSided90: each message is Alice's with probability 0.9
 *  - poisson:    two independent Poisson processes, 1 msg/s each, relay latency
 *                0.15 s + Exp(mean 0.35 s) capped at 3 s, FIFO per direction, so
 *                messages cross in flight (both sides send before seeing the other's).
 */
export function schedule(traffic: Traffic, n: number, seed: number): Slot[] {
  const r = rng(seed * 2654435761 + traffic.length);
  const out: Slot[] = [{ from: "alice", t: 0, lat: 0 }];
  if (traffic === "poisson") {
    const exp = (mean: number) => -Math.log(1 - r()) * mean;
    let tA = 1 + exp(1);
    let tB = 1 + exp(1);
    while (out.length < n) {
      const lat = Math.min(3, 0.15 + exp(0.35));
      if (tA <= tB) {
        out.push({ from: "alice", t: tA, lat });
        tA += exp(1);
      } else {
        out.push({ from: "bob", t: tB, lat });
        tB += exp(1);
      }
    }
    return out;
  }
  for (let i = 1; i < n; i++) {
    let from: "alice" | "bob";
    if (traffic === "alternate") from = i % 2 === 0 ? "alice" : "bob";
    else if (traffic === "burst5") from = Math.floor(i / 5) % 2 === 0 ? "alice" : "bob";
    else from = r() < 0.9 ? "alice" : "bob";
    out.push({ from, t: i, lat: 0 });
  }
  return out;
}

// ---------------------------------------------------------------------------
// One conversation

export interface MsgRecord {
  idx: number;
  from: "alice" | "bob";
  sendT: number;
  deliverT: number;
  /** Global delivery order (0-based). */
  deliverSeq: number;
  epoch: number;
  n: number;
  pn: number;
  ratchetData: "init" | "kem" | "none";
  headerBytes: number;
  bodyBytes: number;
  binaryBytes: number;
  jsonBytes: number;
  kind: "handshake" | "root" | "chain";
  encKem: Counts;
  decKem: Counts;
  prekeyKemOps: number;
  encMs: number;
  encStoreMs: number;
  decMs: number;
  decStoreMs: number;
  skippedAlice: number;
  skippedBob: number;
}

export interface Snapshot {
  k: number;
  t: number;
  store: MemorySessionStore;
  state: SessionState;
  /** Number of Bob->Alice messages Alice had decrypted when the snapshot was taken. */
  aliceRecvCount: number;
}

export interface Conversation {
  suite: KemSuite;
  K: number;
  traffic: Traffic;
  seed: number;
  msgs: MsgRecord[];
  envs: EnvelopeV1[];
  /** Bob->Alice message indices in the order Alice decrypted them. */
  aliceRecvOrder: number[];
  snapshots: Snapshot[];
  alice: Party;
  dir: Directory;
  now: () => number;
}

const te = new TextEncoder();
const td = new TextDecoder();
/** 100-byte plaintext, the same size as E5's steady-state message. */
const plaintext = (i: number) => te.encode(`m${i} `.padEnd(100, "."));

export interface ConversationOpts {
  suite: KemSuite;
  K: number;
  traffic: Traffic;
  seed: number;
  messages: number;
  snapshotsAt: number[];
}

export async function runConversation(o: ConversationOpts): Promise<Conversation> {
  instrumentKems();
  let simT = 0;
  const now = () => 1_800_000_000_000 + Math.round(simT * 1000);
  const dir = new Directory();
  const mo = { suite: o.suite, K: o.K, now };
  const alice = await makeParty(dir, "alice", mo);
  const bob = await makeParty(dir, "bob", mo);
  const party = { alice, bob };
  const slots = schedule(o.traffic, o.messages, o.seed);
  const snapAt = new Set(o.snapshotsAt);

  const msgs: MsgRecord[] = [];
  const envs: EnvelopeV1[] = [];
  const aliceRecvOrder: number[] = [];
  const snapshots: Snapshot[] = [];
  const queues: Record<"alice" | "bob", { at: number; idx: number }[]> = { alice: [], bob: [] }; // keyed by receiver
  const lastAt = { alice: -Infinity, bob: -Infinity };
  let deliverSeq = 0;

  const skippedOf = async (p: Party, peer: string) => (await p.store.load(peer))?.session?.skipped.length ?? 0;

  async function deliverOne(to: "alice" | "bob"): Promise<void> {
    const { at, idx } = queues[to].shift()!;
    simT = Math.max(simT, at);
    const p = party[to];
    const before = readCounters();
    const s0 = p.timed.ms;
    const t0 = performance.now();
    const res = await p.sm.decrypt(envs[idx]);
    const dt = performance.now() - t0;
    const after = readCounters();
    if (td.decode(res.plaintext) !== td.decode(plaintext(idx))) throw new Error(`plaintext mismatch at ${idx}`);
    const m = msgs[idx];
    m.decMs = dt;
    m.decStoreMs = p.timed.ms - s0;
    m.decKem = diff(after.ratchet, before.ratchet);
    m.prekeyKemOps += total(diff(after.prekey, before.prekey));
    m.deliverT = at;
    m.deliverSeq = deliverSeq++;
    if (to === "alice") aliceRecvOrder.push(idx);
    m.skippedAlice = await skippedOf(alice, "bob");
    m.skippedBob = await skippedOf(bob, "alice");
  }

  async function deliverUntil(t: number): Promise<void> {
    for (;;) {
      const a = queues.alice[0];
      const b = queues.bob[0];
      const next = !a ? (b ? "bob" : null) : !b ? "alice" : a.at <= b.at ? "alice" : "bob";
      if (!next || queues[next][0].at > t) return;
      await deliverOne(next);
    }
  }

  for (let i = 0; i < slots.length; i++) {
    const slot = slots[i];
    await deliverUntil(slot.t);
    simT = Math.max(simT, slot.t);
    if (snapAt.has(i)) {
      const store = alice.store.clone();
      snapshots.push({
        k: i,
        t: slot.t,
        store,
        state: (await store.load("bob"))!.session!,
        aliceRecvCount: aliceRecvOrder.length,
      });
    }
    const p = party[slot.from];
    const to = slot.from === "alice" ? "bob" : "alice";
    const before = readCounters();
    const s0 = p.timed.ms;
    const t0 = performance.now();
    const env = await p.sm.encrypt(to, plaintext(i), "text");
    const dt = performance.now() - t0;
    const after = readCounters();
    const parsed = parseEnvelope(env);
    const hb = headerBytes(parsed.header).length;
    envs.push(env);
    msgs.push({
      idx: i,
      from: slot.from,
      sendT: slot.t,
      deliverT: NaN,
      deliverSeq: -1,
      epoch: env.epoch,
      n: env.n,
      pn: env.pn,
      ratchetData: env.init ? "init" : env.kem ? "kem" : "none",
      headerBytes: hb,
      bodyBytes: parsed.body.length,
      binaryBytes: encodeBinaryEnvelope(parsed).length,
      jsonBytes: Buffer.byteLength(JSON.stringify(env), "utf8"),
      kind: "chain",
      encKem: diff(after.ratchet, before.ratchet),
      decKem: zero(),
      prekeyKemOps: total(diff(after.prekey, before.prekey)),
      encMs: dt,
      encStoreMs: p.timed.ms - s0,
      decMs: NaN,
      decStoreMs: NaN,
      skippedAlice: 0,
      skippedBob: 0,
    });
    const at = Math.max(lastAt[to], slot.t + slot.lat);
    lastAt[to] = at;
    queues[to].push({ at, idx: i });
    if (slot.lat === 0) await deliverUntil(slot.t);
  }
  await deliverUntil(Infinity);

  for (const m of msgs) {
    m.kind = m.prekeyKemOps > 0 ? "handshake" : total(m.encKem) + total(m.decKem) > 0 ? "root" : "chain";
  }
  return { suite: o.suite, K: o.K, traffic: o.traffic, seed: o.seed, msgs, envs, aliceRecvOrder, snapshots, alice, dir, now };
}

// ---------------------------------------------------------------------------
// Passive attacker Eve with Alice's state at snapshot k

export interface SnapshotResult {
  suite: KemSuite;
  K: number;
  traffic: Traffic;
  seed: number;
  k: number;
  /** Alice's state at the snapshot. */
  sendEpoch: number;
  recvEpoch: number;
  ns: number;
  dkPending: boolean;
  peerEkPending: boolean;
  /** Messages with index >= k that Eve can read. */
  exposedAfter: number;
  exposedAliceToBob: number;
  exposedBobToAlice: number;
  /** Bob->Alice messages sent before k but still in flight at the snapshot that Eve can read. */
  exposedInFlight: number;
  /** Messages from k up to and including the last one Eve can read (0 if none). */
  healMsgs: number;
  /** False if the transcript ended before both directions went dark: healMsgs is then a lower bound. */
  healed: boolean;
  /** Index of Alice's first message after k on a new epoch (her next ratchet step), or -1. */
  aliceRatchetIdx: number;
  /** Messages at or after aliceRatchetIdx that Eve can still read (spec 9 wording for K = 1). */
  exposedAfterAliceRatchet: number;
  /** Messages where what Eve could read differs from the spec-9 exposure rule. */
  predicateMismatches: number;
  mismatchDetail: string;
  /** Earlier messages (already processed by Alice) Eve could open with the snapshot: must be 0. */
  fsChecked: number;
  fsOpened: number;
}

/**
 * Spec section 9 exposure rule for a passive attacker holding Alice's state s:
 *  - Alice->Bob: exposed iff epoch = s.sendEpoch (Eve walks the stolen sending chain);
 *  - Bob->Alice: exposed iff epoch <= s.recvEpoch, or epoch = s.sendEpoch + 1 while
 *    Alice's ourDk was pending (Bob encapsulates his next epoch to the stolen dk).
 */
export function predictedExposed(s: SessionState, from: "alice" | "bob", epoch: number): boolean {
  if (from === "alice") return epoch === s.sendEpoch;
  return epoch <= s.recvEpoch || (epoch === s.sendEpoch + 1 && s.ourDk !== null);
}

async function tryMk(mk: Uint8Array, env: EnvelopeV1): Promise<boolean> {
  const parsed = parseEnvelope(env);
  const { key, iv } = await messageKeyAndIv(mk);
  try {
    await aesGcmDecrypt(key, iv, parsed.body, headerAad(parsed.header));
    return true;
  } catch {
    return false;
  }
}

/** Walks a chain key forward from position `from` to `n` and tries mk_n. */
async function tryChain(ck: Uint8Array | null, from: number, n: number, env: EnvelopeV1): Promise<boolean> {
  if (!ck || n < from) return false;
  let c = ck;
  for (let i = from; i < n; i++) c = (await kdfChain(c)).ck;
  return tryMk((await kdfChain(c)).mk, env);
}

export async function analyseSnapshot(c: Conversation, snap: Snapshot): Promise<SnapshotResult> {
  const s = snap.state;
  const mo = { suite: c.suite, K: c.K, now: c.now };
  const alice = c.alice;
  const eve = manager(alice, c.dir, snap.store.clone(), mo);
  const exposed = new Map<number, boolean>();

  // Bob -> Alice after the snapshot (including messages in flight at k): Eve gets a copy of
  // every envelope and feeds it to her SessionManager in Alice's delivery order.
  for (const idx of c.aliceRecvOrder.slice(snap.aliceRecvCount)) {
    let ok = false;
    try {
      const r = await eve.decrypt(c.envs[idx]);
      ok = td.decode(r.plaintext) === td.decode(plaintext(idx));
    } catch {
      ok = false;
    }
    exposed.set(idx, ok);
  }
  // Alice -> Bob after the snapshot: Eve walks the stolen sending chain (n only grows).
  let eveCk = s.cks;
  let eveN = s.ns;
  for (const m of c.msgs) {
    if (m.idx < snap.k || m.from !== "alice") continue;
    let ok = false;
    if (eveCk && m.epoch === s.sendEpoch && m.n >= eveN) {
      while (eveN < m.n) {
        eveCk = (await kdfChain(eveCk)).ck;
        eveN++;
      }
      const { mk, ck } = await kdfChain(eveCk);
      eveCk = ck;
      eveN++;
      ok = await tryMk(mk, c.envs[m.idx]);
    }
    exposed.set(m.idx, ok);
  }

  let exposedAfter = 0,
    exA = 0,
    exB = 0,
    inFlight = 0,
    lastExposed = -1,
    mismatches = 0;
  const detail: string[] = [];
  for (const [idx, ok] of exposed) {
    const m = c.msgs[idx];
    const pred = predictedExposed(s, m.from, m.epoch);
    if (pred !== ok) {
      mismatches++;
      if (detail.length < 5) detail.push(`#${idx} ${m.from} e${m.epoch} n${m.n} eve=${ok} rule=${pred}`);
    }
    if (!ok) continue;
    if (idx < snap.k) {
      inFlight++;
      continue;
    }
    exposedAfter++;
    if (m.from === "alice") exA++;
    else exB++;
    lastExposed = Math.max(lastExposed, idx);
  }

  // Healed = the last post-k message in each direction is dark. Exposure is a prefix of each
  // direction's epochs (epochs only grow), so this means Eve is locked out for good.
  const lastDark = (from: "alice" | "bob") => {
    const after = c.msgs.filter((m) => m.idx >= snap.k && m.from === from);
    return after.length > 0 && exposed.get(after[after.length - 1].idx) === false;
  };
  const healed = lastDark("alice") && lastDark("bob");
  const aliceRatchet = c.msgs.find((m) => m.idx >= snap.k && m.from === "alice" && m.epoch > s.sendEpoch);
  const aliceRatchetIdx = aliceRatchet ? aliceRatchet.idx : -1;
  let exposedAfterAliceRatchet = 0;
  if (aliceRatchetIdx >= 0) for (const [idx, ok] of exposed) if (ok && idx >= aliceRatchetIdx) exposedAfterAliceRatchet++;

  // Forward secrecy: every message Alice had already sent or decrypted before k must stay closed.
  const fsEve = manager(alice, c.dir, snap.store.clone(), mo);
  const before = new Set(c.aliceRecvOrder.slice(0, snap.aliceRecvCount));
  let fsChecked = 0,
    fsOpened = 0;
  for (const m of c.msgs) {
    if (m.idx >= snap.k) break;
    if (m.from === "bob" && !before.has(m.idx)) continue; // still in flight: Alice's future, not her past
    fsChecked++;
    const env = c.envs[m.idx];
    let opened = false;
    const sk = s.skipped.find((x) => x.epoch === m.epoch && x.n === m.n);
    if (sk) opened = await tryMk(sk.mk, env);
    if (!opened && m.from === "alice" && m.epoch === s.sendEpoch) opened = await tryChain(s.cks, s.ns, m.n, env);
    if (!opened && m.from === "bob" && m.epoch === s.recvEpoch) opened = await tryChain(s.ckr, s.nr, m.n, env);
    if (!opened && m.from === "bob") {
      try {
        await fsEve.decrypt(env);
        opened = true;
      } catch {
        /* expected: DUPLICATE / STALE_EPOCH */
      }
    }
    if (opened) fsOpened++;
  }

  return {
    suite: c.suite,
    K: c.K,
    traffic: c.traffic,
    seed: c.seed,
    k: snap.k,
    sendEpoch: s.sendEpoch,
    recvEpoch: s.recvEpoch,
    ns: s.ns,
    dkPending: s.ourDk !== null,
    peerEkPending: s.peerEk !== null,
    exposedAfter,
    exposedAliceToBob: exA,
    exposedBobToAlice: exB,
    exposedInFlight: inFlight,
    healMsgs: lastExposed >= 0 ? lastExposed - snap.k + 1 : 0,
    healed,
    aliceRatchetIdx,
    exposedAfterAliceRatchet,
    predicateMismatches: mismatches,
    mismatchDetail: detail.join("; "),
    fsChecked,
    fsOpened,
  };
}
