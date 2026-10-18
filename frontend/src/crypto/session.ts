/**
 * SessionManager: the authoritative Krypt v1 state machine (spec sections 4-7, 11).
 *
 * Rules this file enforces, in one place:
 *  - Every encrypt/decrypt for a peer runs inside one named lock and reloads
 *    the state from the store inside it (no stale copies, no two writers).
 *  - encrypt persists the advanced sending chain BEFORE it encrypts, so a
 *    message key can never be used twice even after a crash.
 *  - decrypt works on a copy and commits only after AES-GCM verifies; on any
 *    error it throws DecryptError and nothing (session, prekeys, replay
 *    memory) has changed. One exception: an init that authenticates but
 *    loses the simultaneous-initiation tie-break is tombstoned before
 *    SESSION_SUPERSEDED is thrown (spec 4.5); the live session is untouched.
 *  - A root step happens only when a new peer key arrives (receive step) or
 *    when we next send after that (send step), never because of timing.
 */
import { compareBytes, ctEqual, toBase64url, utf8, wipe } from "./encoding";
import {
  headerAad,
  parseEnvelope,
  toWire,
  MAX_CONTENT_TYPE_BYTES,
  MAX_NAME_BYTES,
  MAX_PLAINTEXT_BYTES,
  type EnvelopeV1,
  type Envelope,
  type Header,
} from "./envelope";
import { DecryptError, HandshakeError } from "./errors";
import { initiate, respond } from "./handshake";
import { aesGcmDecrypt, aesGcmEncrypt, kdfChain, kdfRoot, messageKeyAndIv, rootContext } from "./kdf";
import { MLDSA87, isKemSuite, ratchetKem, type KemSuite } from "./pq";
import { parseIdentityKey, verifyBundle, type PrekeyBundleWire, type PrekeyStore } from "./prekeys";
import {
  MAX_TOMBSTONES,
  type PeerRecord,
  type SessionState,
  type SessionStore,
  type SkippedKey,
} from "./session-store";

export const MAX_SKIP = 1000;
export const MAX_SKIPPED_TOTAL = 2000;
export const SKIPPED_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_COUNTER = 0xffffffff;

export type LockFn = <T>(name: string, fn: () => Promise<T>) => Promise<T>;

export interface SessionManagerOptions {
  self: { username: string; identity: { dsaPub: Uint8Array; dsaSec: Uint8Array } };
  store: SessionStore;
  prekeys: PrekeyStore;
  /** GET /bundle/:user. Claims one OPK on the server. */
  fetchBundle: (username: string) => Promise<PrekeyBundleWire>;
  /** The peer's identityKey JSON (same format as bundle.identityKey), without claiming an OPK. */
  fetchIdentity: (username: string) => Promise<string>;
  /** Key-transparency / pinning hook. Default: accept. */
  trustIdentity?: (username: string, dsaPub: Uint8Array) => Promise<boolean>;
  /** Ratchet suite for sessions this side initiates. Default "mlkem1024". */
  suite?: KemSuite;
  /** Sparse mode K (spec 5.6). Default 1. */
  ratchetEveryK?: number;
  /** Cross-tab lock. Default: navigator.locks if present, else an in-process mutex. */
  lock?: LockFn;
  /** Millisecond clock (tests). Default Date.now. */
  now?: () => number;
}

export interface DecryptResult {
  peer: string;
  plaintext: Uint8Array;
  contentType: string;
  sessionId: string;
  epoch: number;
  n: number;
}

export interface SessionStatus {
  sessionId: string;
  role: "initiator" | "responder";
  suite: KemSuite;
  /** True once anything from the peer has been authenticated on this session. */
  established: boolean;
  /** Highest epoch seen in either direction. */
  epoch: number;
  sendEpoch: number;
  recvEpoch: number;
  lastRatchetAt: number;
  createdAt: number;
}

/** In-process mutex keyed by name: a promise chain per name. */
export function createMutexLock(): LockFn {
  const tails = new Map<string, Promise<unknown>>();
  return async <T>(name: string, fn: () => Promise<T>): Promise<T> => {
    const prev = tails.get(name) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => undefined);
    tails.set(name, tail);
    try {
      return await run;
    } finally {
      if (tails.get(name) === tail) tails.delete(name);
    }
  };
}

interface NavigatorLocks {
  request<T>(name: string, cb: () => Promise<T>): Promise<T>;
}

function defaultLock(): LockFn {
  const locks = (globalThis.navigator as { locks?: NavigatorLocks } | undefined)?.locks;
  if (locks && typeof locks.request === "function") {
    return <T>(name: string, fn: () => Promise<T>) => locks.request<T>(name, () => fn());
  }
  return createMutexLock();
}

const fail = (code: ConstructorParameters<typeof DecryptError>[0], detail?: string): never => {
  throw new DecryptError(code, detail);
};

function validName(s: string): boolean {
  const len = utf8(s).length;
  return len >= 1 && len <= MAX_NAME_BYTES;
}

export class SessionManager {
  private readonly self: SessionManagerOptions["self"];
  private readonly store: SessionStore;
  private readonly prekeys: PrekeyStore;
  private readonly fetchBundle: SessionManagerOptions["fetchBundle"];
  private readonly fetchIdentity: SessionManagerOptions["fetchIdentity"];
  private readonly trustIdentity: NonNullable<SessionManagerOptions["trustIdentity"]>;
  private readonly suite: KemSuite;
  private readonly K: number;
  private readonly lock: LockFn;
  private readonly now: () => number;

  constructor(opts: SessionManagerOptions) {
    if (!validName(opts.self.username)) throw new Error("invalid username");
    if (opts.self.identity.dsaPub.length !== MLDSA87.publicKey || opts.self.identity.dsaSec.length !== MLDSA87.secretKey) {
      throw new Error("identity must be an ML-DSA-87 key pair");
    }
    const K = opts.ratchetEveryK ?? 1;
    if (!Number.isInteger(K) || K < 1) throw new Error("ratchetEveryK must be a positive integer");
    this.self = opts.self;
    this.store = opts.store;
    this.prekeys = opts.prekeys;
    this.fetchBundle = opts.fetchBundle;
    this.fetchIdentity = opts.fetchIdentity;
    this.trustIdentity = opts.trustIdentity ?? (async () => true);
    this.suite = opts.suite ?? "mlkem1024";
    this.K = K;
    this.lock = opts.lock ?? defaultLock();
    this.now = opts.now ?? Date.now;
  }

  private lockName(peer: string) {
    return `krypt-session:${this.self.username}:${peer}`;
  }

  /**
   * A session saved under a ratchet suite that no longer exists (ML-KEM-768 or
   * X-Wing, removed before v1) is closed here, so the next send runs a fresh
   * handshake instead of crashing in ratchetKem().
   */
  private async loadRecord(peer: string): Promise<PeerRecord> {
    const rec = (await this.store.load(peer)) ?? { session: null, closed: [] };
    if (rec.session && !isKemSuite(rec.session.suite)) {
      return { session: null, closed: tombstone(rec.closed, toBase64url(rec.session.sessionId)) };
    }
    return rec;
  }

  // -------------------------------------------------------------------------
  // Sending

  /**
   * Encrypts `plaintext` for `peer`, starting a session (Krypt-X3K) if there is
   * none. The advanced chain is persisted before the envelope is built.
   */
  async encrypt(peer: string, plaintext: Uint8Array, contentType: string): Promise<EnvelopeV1> {
    if (!validName(peer) || peer === this.self.username) throw new Error("invalid peer");
    const ctLen = utf8(contentType).length;
    if (ctLen < 1 || ctLen > MAX_CONTENT_TYPE_BYTES) throw new Error("invalid contentType");
    if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error("plaintext too large");

    return this.lock(this.lockName(peer), async () => {
      const now = this.now();
      const rec = await this.loadRecord(peer);
      const s = rec.session ?? (await this.startSession(peer, now));

      // Send step: Bob's bootstrap (no sending chain yet), or a fresh peer key
      // is waiting and we have sent K messages on the current chain.
      if (s.cks === null || (s.peerEk !== null && s.ns >= this.K)) await this.sendStep(s, now);
      if (s.ns >= MAX_COUNTER) throw new Error("sending chain exhausted");

      const { mk, ck } = await kdfChain(s.cks!);
      const header: Header = {
        v: 1,
        suite: s.suite,
        sessionId: s.sessionId,
        from: this.self.username,
        to: peer,
        contentType,
        epoch: s.sendEpoch,
        n: s.ns,
        pn: s.pn,
        // Ratchet data (or the init header in epoch 0) rides on every message
        // of the chain until the peer proves it has it.
        kem: s.peerAcked ? null : s.sendKem,
        init: s.peerAcked ? null : s.init,
      };
      s.cks = ck;
      s.ns += 1;
      purgeExpired(s, now);

      // No-rollback rule 1: persist first. If this throws, nothing was encrypted.
      await this.store.save(peer, { session: s, closed: rec.closed });

      const { key, iv } = await messageKeyAndIv(mk);
      const body = await aesGcmEncrypt(key, iv, plaintext, headerAad(header));
      wipe(mk, key);
      return toWire({ header, body });
    });
  }

  private async startSession(peer: string, now: number): Promise<SessionState> {
    const bundle = verifyBundle(await this.fetchBundle(peer), peer);
    if (!(await this.trustIdentity(peer, bundle.identityDsaPub))) {
      throw new HandshakeError("UNTRUSTED_IDENTITY", "identity key refused by trustIdentity");
    }
    const r = await initiate({
      self: { username: this.self.username, dsaPub: this.self.identity.dsaPub, dsaSec: this.self.identity.dsaSec },
      bundle,
      suite: this.suite,
    });
    return {
      v: 1,
      sessionId: r.sessionId,
      peer,
      role: "initiator",
      suite: this.suite,
      rk: r.rk,
      sendEpoch: 0,
      cks: r.ck,
      ns: 0,
      pn: 0,
      sendKem: null,
      init: r.init,
      peerAcked: false,
      ourEk: r.ourEk,
      ourDk: r.ourDk,
      peerEk: null,
      recvEpoch: -1,
      ckr: null,
      nr: 0,
      skipped: [],
      established: false,
      createdAt: now,
      lastRatchetAt: now,
    };
  }

  /** Spec 5.4 step 2: encapsulate to the peer's newest key and start a new sending epoch. */
  private async sendStep(s: SessionState, now: number): Promise<void> {
    if (!s.peerEk) throw new Error("send step without a peer ratchet key");
    // Invariant: our previous dk was consumed by the receive step that delivered peerEk.
    if (s.ourDk) throw new Error("send step while our ratchet key is still pending");
    const kem = ratchetKem(s.suite);
    const { cipherText: ct, sharedSecret: ss } = kem.encapsulate(s.peerEk);
    const fresh = kem.keygen();
    // Epoch rule: the new chain's epoch, i.e. one after the chain that delivered peerEk.
    const epoch = s.recvEpoch + 1;
    const out = await kdfRoot(s.rk, ss, await rootContext(epoch, s.peerEk, ct));
    const [oldRk, oldCks] = [s.rk, s.cks];
    s.rk = out.rk;
    s.pn = oldCks ? s.ns : 0;
    s.cks = out.ck;
    wipe(ss, oldRk, oldCks);
    s.ns = 0;
    s.sendEpoch = epoch;
    s.sendKem = { ct, ek: fresh.publicKey };
    s.ourEk = fresh.publicKey;
    s.ourDk = fresh.secretKey;
    s.peerEk = null;
    s.peerAcked = false;
    s.init = null;
    s.lastRatchetAt = now;
  }

  // -------------------------------------------------------------------------
  // Receiving

  /** Decrypts an untrusted envelope (JSON string or parsed object). */
  async decrypt(input: unknown): Promise<DecryptResult> {
    const env = parseEnvelope(input);
    const h = env.header;
    if (h.to !== this.self.username) fail("NOT_FOR_ME");
    if (h.from === this.self.username) fail("MALFORMED", "message from ourselves");
    const peer = h.from;

    return this.lock(this.lockName(peer), async () => {
      const now = this.now();
      const rec = await this.loadRecord(peer);
      const live = rec.session;
      // A repeated init header for the live session is the same session.
      if (live && ctEqual(live.sessionId, h.sessionId)) return this.receive(peer, rec, live, env, now);
      if (rec.closed.includes(toBase64url(h.sessionId))) fail("SESSION_CLOSED");
      if (!h.init) fail("UNKNOWN_SESSION");
      return this.acceptInit(peer, rec, env, now);
    });
  }

  /** Spec 5.5: a message on the live session. `s` is a fresh copy from the store. */
  private async receive(
    peer: string,
    rec: PeerRecord,
    s: SessionState,
    env: Envelope,
    now: number,
  ): Promise<DecryptResult> {
    const h = env.header;
    if (h.suite !== s.suite) fail("BAD_EPOCH", "suite does not match the session");
    const peerParity = s.role === "initiator" ? 1 : 0;
    if (h.epoch % 2 !== peerParity) fail("BAD_EPOCH", "epoch has our parity");
    purgeExpired(s, now);

    const fresh: SkippedKey[] = [];
    let mk: Uint8Array;
    const cached = s.skipped.findIndex((k) => k.epoch === h.epoch && k.n === h.n);
    if (cached >= 0) {
      mk = s.skipped[cached].mk;
      s.skipped.splice(cached, 1);
    } else if (h.epoch === s.recvEpoch) {
      if (h.n < s.nr) fail("DUPLICATE");
      mk = await advanceReceivingChain(s, h.n, fresh, now);
    } else if (h.epoch > s.recvEpoch) {
      // A new chain from the peer: it must encapsulate to our pending key.
      if (h.epoch !== s.sendEpoch + 1 || !s.ourDk || !s.ourEk || !h.kem) fail("BAD_EPOCH", "unexpected new epoch");
      if (s.ckr) {
        // Finish the previous receiving chain up to the peer's pn.
        if (h.pn < s.nr) fail("BAD_HEADER", "pn is below what we already received");
        await skipReceivingChain(s, h.pn, fresh, now);
      }
      // Receive step (spec 5.5 step 6).
      const ss = ratchetKem(s.suite).decapsulate(h.kem!.ct, s.ourDk!);
      const out = await kdfRoot(s.rk, ss, await rootContext(h.epoch, s.ourEk!, h.kem!.ct));
      s.rk = out.rk;
      s.ckr = out.ck;
      s.nr = 0;
      s.recvEpoch = h.epoch;
      s.ourDk = null;
      s.ourEk = null;
      s.peerEk = h.kem!.ek;
      s.peerAcked = true;
      s.init = null;
      s.lastRatchetAt = now;
      // Keep skipped keys of the current and previous receiving epoch only.
      s.skipped = s.skipped.filter((k) => k.epoch >= h.epoch - 2);
      mk = await advanceReceivingChain(s, h.n, fresh, now);
    } else {
      return fail("STALE_EPOCH");
    }

    const plaintext = await openBody(mk, env);
    s.established = true;
    addSkipped(s, fresh);
    await this.store.save(peer, { session: s, closed: rec.closed });
    return result(peer, h, plaintext);
  }

  /** Spec 4.2 and 4.5: an init header for a session we do not have. */
  private async acceptInit(peer: string, rec: PeerRecord, env: Envelope, now: number): Promise<DecryptResult> {
    const h = env.header;
    if (h.pn !== 0 || h.kem) fail("MALFORMED", "init header with ratchet fields");

    // Simultaneous initiation: our own unconfirmed session wins if its id is
    // smaller (raw bytes, not base64url strings).
    const live = rec.session;
    if (live && live.role === "initiator" && !live.established && compareBytes(h.sessionId, live.sessionId) >= 0) {
      return this.rejectSuperseded(peer, rec, env, now);
    }

    const a = await this.authenticateInit(peer, env, now);

    // Commit, in an order that is safe if we crash part-way: the session
    // first (a replay then hits the live-session path), then the OPK deletion
    // and the session-id memory.
    addSkipped(a.session, a.fresh);
    const closed = live ? tombstone(rec.closed, toBase64url(live.sessionId)) : rec.closed;
    await this.store.save(peer, { session: a.session, closed });
    await this.consumeInit(a);
    return result(peer, h, a.plaintext);
  }

  /**
   * Spec 4.5, losing side of the tie-break. If the init authenticates, its id
   * is tombstoned (and its OPK and session-id memory handled exactly like an
   * accepted init) before SESSION_SUPERSEDED is thrown, so a later or
   * relay-replayed copy cannot take the "peer started over" path once our
   * session is confirmed. The live session itself is never touched. An init
   * that does not authenticate changes nothing.
   */
  private async rejectSuperseded(peer: string, rec: PeerRecord, env: Envelope, now: number): Promise<never> {
    let a: AuthenticatedInit;
    try {
      a = await this.authenticateInit(peer, env, now);
    } catch (err) {
      if (err instanceof DecryptError) fail("SESSION_SUPERSEDED", "init did not authenticate; nothing recorded");
      throw err;
    }
    wipe(a.session.rk, a.session.ckr, a.plaintext, ...a.fresh.map((k) => k.mk));
    await this.store.save(peer, { session: rec.session, closed: tombstone(rec.closed, a.sid) });
    await this.consumeInit(a);
    return fail("SESSION_SUPERSEDED");
  }

  /** Deletes the init's OPK and records its id in the SPK's session-id memory. */
  private async consumeInit(a: AuthenticatedInit): Promise<void> {
    if (a.opkId !== null) await this.prekeys.deleteOneTimePrekey(a.opkId);
    await this.prekeys.recordAcceptedSession(a.spkId, a.sid);
  }

  /**
   * Spec 4.2 steps 5-12 up to (not including) the commit: identity, prekeys,
   * replay memory, transcript and AES-GCM of the first message. Pure: nothing
   * is written.
   */
  private async authenticateInit(peer: string, env: Envelope, now: number): Promise<AuthenticatedInit> {
    const h = env.header;
    const init = h.init!;
    let ikA: Uint8Array;
    try {
      ikA = parseIdentityKey(await this.fetchIdentity(peer));
    } catch {
      return fail("UNTRUSTED_IDENTITY", "peer identity key unavailable or malformed");
    }
    if (!(await this.trustIdentity(peer, ikA))) fail("UNTRUSTED_IDENTITY");

    const spk = await this.prekeys.getSignedPrekey(init.spkId);
    if (!spk) fail("UNKNOWN_PREKEY", "signed prekey");
    // Session-id memory: every accepted handshake is remembered under its SPK.
    const sid = toBase64url(h.sessionId);
    if (await this.prekeys.hasAcceptedSession(init.spkId, sid)) fail("INIT_REPLAY");
    const opk = init.opkId === null ? null : await this.prekeys.getOneTimePrekey(init.opkId);
    if (init.opkId !== null && !opk) fail("UNKNOWN_PREKEY", "one-time prekey");

    const r = await respond({
      self: { username: this.self.username, dsaPub: this.self.identity.dsaPub },
      initiator: { username: peer, dsaPub: ikA },
      suite: h.suite,
      init,
      spk: spk!,
      opk: opk ?? null,
    });
    if (!ctEqual(r.sessionId, h.sessionId)) fail("BAD_SIGNATURE", "sessionId is not H(T)");

    const s: SessionState = {
      v: 1,
      sessionId: r.sessionId,
      peer,
      role: "responder",
      suite: h.suite,
      rk: r.rk,
      sendEpoch: -1,
      cks: null,
      ns: 0,
      pn: 0,
      sendKem: null,
      init: null,
      peerAcked: true,
      ourEk: null,
      ourDk: null,
      peerEk: r.peerEk,
      recvEpoch: 0,
      ckr: r.ck,
      nr: 0,
      skipped: [],
      established: true,
      createdAt: now,
      lastRatchetAt: now,
    };
    const fresh: SkippedKey[] = [];
    const mk = await advanceReceivingChain(s, h.n, fresh, now);
    const plaintext = await openBody(mk, env);
    return { session: s, fresh, plaintext, sid, spkId: init.spkId, opkId: init.opkId };
  }

  // -------------------------------------------------------------------------
  // Status

  async getStatus(peer: string): Promise<SessionStatus | null> {
    const s = (await this.store.load(peer))?.session;
    if (!s) return null;
    return {
      sessionId: toBase64url(s.sessionId),
      role: s.role,
      suite: s.suite,
      established: s.established,
      epoch: Math.max(s.sendEpoch, s.recvEpoch),
      sendEpoch: s.sendEpoch,
      recvEpoch: s.recvEpoch,
      lastRatchetAt: s.lastRatchetAt,
      createdAt: s.createdAt,
    };
  }

  /** Forgets the session and tombstones its id, so its messages and inits are refused. */
  async closeSession(peer: string): Promise<void> {
    await this.lock(this.lockName(peer), async () => {
      const rec = await this.loadRecord(peer);
      if (!rec.session) return;
      await this.store.save(peer, { session: null, closed: tombstone(rec.closed, toBase64url(rec.session.sessionId)) });
    });
  }
}

interface AuthenticatedInit {
  session: SessionState;
  fresh: SkippedKey[];
  plaintext: Uint8Array;
  sid: string;
  spkId: number;
  opkId: number | null;
}

/** Appends `sid` to the tombstone list (once), keeping the newest MAX_TOMBSTONES. */
function tombstone(closed: string[], sid: string): string[] {
  return [...closed.filter((c) => c !== sid), sid].slice(-MAX_TOMBSTONES);
}

// ---------------------------------------------------------------------------
// Helpers (all operate on the working copy of the state)

/** Derives keys nr..n-1 into `fresh` and returns mk_n; enforces MAX_SKIP. */
async function advanceReceivingChain(s: SessionState, n: number, fresh: SkippedKey[], now: number): Promise<Uint8Array> {
  await skipReceivingChain(s, n, fresh, now);
  const { mk, ck } = await kdfChain(s.ckr!);
  s.ckr = ck;
  s.nr = n + 1;
  return mk;
}

/** Caches message keys nr..until-1 of the current receiving chain. */
async function skipReceivingChain(s: SessionState, until: number, fresh: SkippedKey[], now: number): Promise<void> {
  if (until - s.nr > MAX_SKIP) fail("TOO_MANY_SKIPPED");
  while (s.nr < until) {
    const { mk, ck } = await kdfChain(s.ckr!);
    fresh.push({ epoch: s.recvEpoch, n: s.nr, mk, expiresAt: now + SKIPPED_TTL_MS });
    s.ckr = ck;
    s.nr += 1;
  }
}

function purgeExpired(s: SessionState, now: number): void {
  s.skipped = s.skipped.filter((k) => k.expiresAt > now);
}

/** Adds newly skipped keys, evicting the oldest beyond MAX_SKIPPED_TOTAL. */
function addSkipped(s: SessionState, fresh: SkippedKey[]): void {
  s.skipped.push(...fresh);
  if (s.skipped.length > MAX_SKIPPED_TOTAL) s.skipped = s.skipped.slice(s.skipped.length - MAX_SKIPPED_TOTAL);
}

async function openBody(mk: Uint8Array, env: Envelope): Promise<Uint8Array> {
  const { key, iv } = await messageKeyAndIv(mk);
  try {
    return await aesGcmDecrypt(key, iv, env.body, headerAad(env.header));
  } catch {
    return fail("AUTH_FAILED");
  } finally {
    wipe(key);
  }
}

function result(peer: string, h: Header, plaintext: Uint8Array): DecryptResult {
  return {
    peer,
    plaintext,
    contentType: h.contentType,
    sessionId: toBase64url(h.sessionId),
    epoch: h.epoch,
    n: h.n,
  };
}
