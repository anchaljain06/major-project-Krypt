/**
 * services/prekeyMaintenance.ts against a fake prekey server: stale one-time
 * prekeys after a lost prekey store, the UNKNOWN_PREKEY reset, its rate
 * limit, and cleanup after a failed upload.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { exportPublicIdentity } from "../src/crypto/mlkem";
import { mldsaKeygen } from "../src/crypto/pq";
import {
  MemoryPrekeyStore,
  createOneTimePrekeys,
  type PrekeyBundleWire,
  type PrekeyWire,
} from "../src/crypto/prekeys";
import { SessionManager, createMutexLock } from "../src/crypto/session";
import { MemorySessionStore } from "../src/crypto/session-store";
import type { Protocol } from "../src/services/protocol";
import { Directory, makeParty, managerFor, recv, te, type Party } from "./helpers";

const api = vi.hoisted(() => ({ apiFetch: vi.fn(), apiPostJson: vi.fn() }));
vi.mock("../src/services/api", () => api);
vi.mock("../src/services/protocol", async () => {
  const { createMutexLock } = await import("../src/crypto/session");
  return { appLock: createMutexLock() };
});

const {
  maintainPrekeys,
  resetOneTimePrekeysAfterUnknown,
  OPK_RESET_MIN_INTERVAL_MS,
  OPK_TARGET,
} = await import("../src/services/prekeyMaintenance");

/** What the backend stores for one user: public prekeys only. */
class FakeServer {
  spk: PrekeyWire | null = null;
  opks: PrekeyWire[] = [];
  deletes = 0;
  uploads = 0;
  failUpload: "http" | "network" | null = null;

  constructor() {
    api.apiFetch.mockImplementation(async (path: string, init: RequestInit = {}) => {
      if (path === "/api/prekeys/count") {
        return Response.json({ oneTimeRemaining: this.opks.length, hasSignedPrekey: this.spk !== null });
      }
      if (path === "/api/prekeys/one-time" && init.method === "DELETE") {
        this.deletes++;
        this.opks = [];
        return Response.json({ success: true, oneTimeRemaining: 0 });
      }
      throw new Error(`unexpected ${init.method ?? "GET"} ${path}`);
    });
    api.apiPostJson.mockImplementation(async (path: string, body: { signedPrekey?: PrekeyWire; oneTimePrekeys?: PrekeyWire[] }) => {
      expect(path).toBe("/api/prekeys");
      if (this.failUpload === "network") throw new TypeError("Failed to fetch");
      if (this.failUpload === "http") return Response.json({ error: "Database error." }, { status: 500 });
      this.uploads++;
      if (body.signedPrekey) this.spk = body.signedPrekey;
      this.opks.push(...(body.oneTimePrekeys ?? []));
      return Response.json({ success: true });
    });
  }

  /** GET /bundle: claims the oldest OPK. */
  bundle(username: string, identityKey: string): PrekeyBundleWire {
    return { username, identityKey, signedPrekey: this.spk!, oneTimePrekey: this.opks.shift() ?? null };
  }
}

function memoryLocalStorage() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: (i: number) => [...m.keys()][i] ?? null,
    get length() {
      return m.size;
    },
  };
}

const kp = mldsaKeygen();
const identity = { dsaPub: kp.publicKey, dsaSec: kp.secretKey };
const identityKey = exportPublicIdentity({ kemPublicKey: new Uint8Array(1568), dsaPublicKey: identity.dsaPub });

function device(prekeys = new MemoryPrekeyStore()) {
  return { username: "alice", keys: { dsaSecretKey: identity.dsaSec }, prekeys } as unknown as Protocol & {
    prekeys: MemoryPrekeyStore;
  };
}

/**
 * Bob starts a session with alice, fetching her bundle from the fake server.
 * Returns his first envelope and an alice that decrypts with `prekeys`.
 */
async function bobMessagesAlice(server: FakeServer, prekeys: MemoryPrekeyStore) {
  const dir = new Directory();
  const bob = await makeParty(dir, "bob");
  const bobKey = dir.entries.get("bob")!.identityKey;
  const alice: Pick<Party, "name" | "sm"> = {
    name: "alice",
    sm: new SessionManager({
      self: { username: "alice", identity },
      store: new MemorySessionStore(),
      prekeys,
      fetchBundle: async () => {
        throw new Error("alice does not initiate here");
      },
      fetchIdentity: async () => bobKey,
      lock: createMutexLock(),
    }),
  };
  bob.sm = managerFor(bob, Object.assign(new Directory(), { fetchBundle: async () => server.bundle("alice", identityKey) }));
  const env = await bob.sm.encrypt("alice", te.encode("hi alice"), "text");
  return { env, alice: alice as Party };
}

let server: FakeServer;
const T0 = 1_800_000_000_000;

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("localStorage", memoryLocalStorage());
  server = new FakeServer();
});

describe("prekey maintenance: one-time prekey hygiene", () => {
  it("first run uploads an SPK and a full batch, without withdrawing anything", async () => {
    const p = device();
    const r = await maintainPrekeys(p, T0);
    expect(r).toMatchObject({ uploadedSignedPrekey: true, uploadedOneTime: OPK_TARGET, resetOneTime: false });
    expect(server.deletes).toBe(0);
    expect(await p.prekeys.countOneTimePrekeys()).toBe(OPK_TARGET);
  });

  it("a healthy device (local halves >= server OPKs) is left alone", async () => {
    const p = device();
    await maintainPrekeys(p, T0);
    server.opks.splice(0, 30); // claimed by peers; their inits are still on the way
    const r = await maintainPrekeys(p, T0 + 1000);
    expect(r).toMatchObject({ uploadedSignedPrekey: false, uploadedOneTime: 0, resetOneTime: false });
    expect(server.deletes).toBe(0);
  });

  it("a lost prekey store is detected on login: server OPKs are withdrawn and replaced", async () => {
    await maintainPrekeys(device(), T0);
    const orphans = server.opks.map((k) => k.keyId);

    // IndexedDB cleared: same account, empty prekey store.
    const fresh = device();
    const r = await maintainPrekeys(fresh, T0 + 1000);
    expect(r).toMatchObject({ resetOneTime: true, uploadedSignedPrekey: true, uploadedOneTime: OPK_TARGET });
    expect(server.deletes).toBe(1);
    expect(server.opks).toHaveLength(OPK_TARGET);
    expect(server.opks.some((k) => orphans.includes(k.keyId))).toBe(false);
    for (const k of server.opks) expect(await fresh.prekeys.getOneTimePrekey(k.keyId)).toBeDefined();

    // A peer that now fetches a bundle gets a usable OPK.
    const { env, alice } = await bobMessagesAlice(server, fresh.prekeys);
    expect(env.init!.opkId).not.toBeNull();
    expect(await recv(alice, env)).toBe("hi alice");
  });

  it("UNKNOWN_PREKEY from a peer's init triggers the reset, at most once per interval", async () => {
    const p = device();
    await maintainPrekeys(p, T0);
    // A loss the count check cannot see: the half of the next OPK the server
    // hands out is gone, but the local count still covers the server's.
    await p.prekeys.deleteOneTimePrekey(server.opks[0].keyId);
    await createOneTimePrekeys(identity.dsaSec, p.prekeys, 1, T0);
    const { env, alice } = await bobMessagesAlice(server, p.prekeys);
    await expect(recv(alice, env)).rejects.toMatchObject({ code: "UNKNOWN_PREKEY" });
    expect((await maintainPrekeys(p, T0 + 500)).resetOneTime).toBe(false);

    const r = await resetOneTimePrekeysAfterUnknown(p, T0 + 1000);
    expect(r).toMatchObject({ resetOneTime: true, uploadedOneTime: OPK_TARGET });
    expect(server.deletes).toBe(1);

    // Forged inits naming unknown OPKs cannot make us churn prekeys.
    expect(await resetOneTimePrekeysAfterUnknown(p, T0 + 2000)).toBeNull();
    expect((await maintainPrekeys(p, T0 + 3000, { resetOneTime: true })).resetOneTime).toBe(false);
    expect(server.deletes).toBe(1);
    expect((await resetOneTimePrekeysAfterUnknown(p, T0 + 1000 + OPK_RESET_MIN_INTERVAL_MS))!.resetOneTime).toBe(true);
    expect(server.deletes).toBe(2);
  });

  for (const failure of ["http", "network"] as const) {
    it(`a failed upload (${failure}) leaves no one-time private halves behind`, async () => {
      const p = device();
      server.failUpload = failure;
      await expect(maintainPrekeys(p, T0)).rejects.toThrow();
      expect(await p.prekeys.countOneTimePrekeys()).toBe(0);
      expect(server.opks).toHaveLength(0);

      // The next run succeeds normally.
      server.failUpload = null;
      const r = await maintainPrekeys(p, T0 + 1000);
      expect(r.uploadedOneTime).toBe(OPK_TARGET);
      expect(await p.prekeys.countOneTimePrekeys()).toBe(OPK_TARGET);
    });
  }
});
