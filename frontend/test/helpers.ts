/**
 * Test world: a fake directory server (bundles, identities) and parties that
 * each own a SessionManager with in-memory stores.
 */
import { exportPublicIdentity } from "../src/crypto/mlkem";
import { mldsaKeygen, type KemSuite } from "../src/crypto/pq";
import {
  MemoryPrekeyStore,
  createPrekeyUpload,
  type PrekeyBundleWire,
  type PrekeyWire,
} from "../src/crypto/prekeys";
import { SessionManager, createMutexLock, type LockFn } from "../src/crypto/session";
import { MemorySessionStore, type SessionStore } from "../src/crypto/session-store";
import type { EnvelopeV1 } from "../src/crypto/envelope";

export const te = new TextEncoder();
export const td = new TextDecoder();

export interface DirEntry {
  identityKey: string;
  signedPrekey: PrekeyWire;
  oneTimePrekeys: PrekeyWire[];
}

/** The relay's prekey directory: hands out one OPK per bundle and deletes it. */
export class Directory {
  entries = new Map<string, DirEntry>();
  /** Optional tamper hook to model a malicious server. */
  tamper?: (b: PrekeyBundleWire) => PrekeyBundleWire;

  async fetchBundle(username: string): Promise<PrekeyBundleWire> {
    const e = this.entries.get(username);
    if (!e) throw new Error(`no such user ${username}`);
    const b: PrekeyBundleWire = {
      username,
      identityKey: e.identityKey,
      signedPrekey: e.signedPrekey,
      oneTimePrekey: e.oneTimePrekeys.shift() ?? null,
    };
    return this.tamper ? this.tamper(b) : b;
  }

  async fetchIdentity(username: string): Promise<string> {
    const e = this.entries.get(username);
    if (!e) throw new Error(`no such user ${username}`);
    return e.identityKey;
  }
}

export interface Party {
  name: string;
  identity: { dsaPub: Uint8Array; dsaSec: Uint8Array };
  store: MemorySessionStore;
  prekeys: MemoryPrekeyStore;
  sm: SessionManager;
}

export interface PartyOptions {
  suite?: KemSuite;
  ratchetEveryK?: number;
  oneTimeCount?: number;
  now?: () => number;
  lock?: LockFn;
  store?: SessionStore;
}

export async function makeParty(dir: Directory, name: string, opts: PartyOptions = {}): Promise<Party> {
  const kp = mldsaKeygen();
  const identity = { dsaPub: kp.publicKey, dsaSec: kp.secretKey };
  const prekeys = new MemoryPrekeyStore();
  const upload = await createPrekeyUpload(identity.dsaSec, prekeys, opts.oneTimeCount ?? 3);
  dir.entries.set(name, {
    // Exactly today's identity format (mlkem.ts); the KEM key is unused by v1.
    identityKey: exportPublicIdentity({ kemPublicKey: new Uint8Array(1568), dsaPublicKey: identity.dsaPub }),
    signedPrekey: upload.signedPrekey,
    oneTimePrekeys: upload.oneTimePrekeys,
  });
  const store = new MemorySessionStore();
  const party: Party = { name, identity, store, prekeys, sm: undefined as unknown as SessionManager };
  party.sm = managerFor(party, dir, opts);
  return party;
}

/** A SessionManager over a party's stores (a second one models a second tab or a stolen copy). */
export function managerFor(
  p: Pick<Party, "name" | "identity" | "store" | "prekeys">,
  dir: Directory,
  opts: PartyOptions = {},
): SessionManager {
  return new SessionManager({
    self: { username: p.name, identity: p.identity },
    store: opts.store ?? p.store,
    prekeys: p.prekeys,
    fetchBundle: (u) => dir.fetchBundle(u),
    fetchIdentity: (u) => dir.fetchIdentity(u),
    suite: opts.suite,
    ratchetEveryK: opts.ratchetEveryK,
    now: opts.now,
    lock: opts.lock ?? createMutexLock(),
  });
}

export async function world(opts: PartyOptions = {}) {
  const dir = new Directory();
  const alice = await makeParty(dir, "alice", opts);
  const bob = await makeParty(dir, "bob", opts);
  return { dir, alice, bob };
}

export async function send(from: Party, to: Party, text: string, contentType = "text"): Promise<EnvelopeV1> {
  return from.sm.encrypt(to.name, te.encode(text), contentType);
}

export async function recv(to: Party, env: unknown): Promise<string> {
  return td.decode((await to.sm.decrypt(env)).plaintext);
}

/** Deep copy of a wire envelope. */
export const copy = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

/** Expect a DecryptError with `code` and an unchanged store + prekey store. */
export async function expectRejected(
  p: Party,
  env: unknown,
  code: string | string[],
  peer = "alice",
): Promise<void> {
  const before = p.store.raw(peer);
  const pk = p.prekeys.fingerprint();
  let err: unknown;
  try {
    await p.sm.decrypt(env);
  } catch (e) {
    err = e;
  }
  const codes = Array.isArray(code) ? code : [code];
  const got = (err as { code?: string } | undefined)?.code;
  if (!err || (err as Error).name !== "DecryptError" || !codes.includes(got!)) {
    throw new Error(`expected DecryptError ${codes.join("|")}, got ${err ? `${(err as Error).name} ${got}` : "success"}`);
  }
  if (p.store.raw(peer) !== before) throw new Error("session state changed on a rejected message");
  if (p.prekeys.fingerprint() !== pk) throw new Error("prekey store changed on a rejected message");
}

/** Flip one bit of a base64url field. */
export function flipB64(s: string, byte = 0, bit = 0): string {
  const b = Buffer.from(s, "base64url");
  b[byte % b.length] ^= 1 << bit;
  return b.toString("base64url");
}

/** Deterministic PRNG for shuffles. */
export function rng(seed: number) {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x / 0x100000000;
  };
}

export function shuffle<T>(a: T[], r: () => number): T[] {
  const out = a.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
