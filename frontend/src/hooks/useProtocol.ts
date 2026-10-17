import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import type { UserIdentityKeys } from "../crypto/mlkem";
import { maintainPrekeys } from "../services/prekeyMaintenance";
import { startProtocol, type Protocol } from "../services/protocol";
import { onSuiteChange } from "../services/settings";
import { socket } from "../services/socket";

/** How often a running tab checks whether the signed prekey is due for rotation. */
const PREKEY_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

/**
 * Starts the user's Krypt v1 Protocol (SessionManager + stores + KT client)
 * once the identity keys are loaded, then keeps prekeys and KT up to date:
 * prekey upload/refill/rotation now, on `prekeys_low` and every few hours;
 * KT self-registration and self-monitoring at start.
 */
export function useProtocol(user: string, keys: UserIdentityKeys | null): Protocol | null {
  const [protocol, setProtocol] = useState<Protocol | null>(null);

  useEffect(() => {
    if (!user || !keys) return;
    let cancelled = false;
    startProtocol(user, keys)
      .then((p) => {
        if (!cancelled) setProtocol(p);
      })
      .catch((err) => {
        console.error("[Krypt] protocol start failed:", err);
        toast.error(`Secure messaging could not start: ${err instanceof Error ? err.message : "unknown error"}`);
      });
    return () => {
      cancelled = true;
    };
  }, [user, keys]);

  const active = protocol && protocol.username === user && protocol.keys === keys ? protocol : null;

  useEffect(() => {
    if (!active) return;
    return onSuiteChange((s) => active.setSuite(s));
  }, [active]);

  useEffect(() => {
    if (!active) return;
    const refresh = () => {
      maintainPrekeys(active).catch((err) => {
        console.error("[Krypt] prekey maintenance failed:", err);
        toast.error("Could not publish your prekeys. Others may not be able to start a chat with you.");
      });
    };
    refresh();
    active.kt
      .registerSelf()
      .then(() => active.kt.monitorSelf())
      .catch((err) => active.kt.noteError(`key transparency check failed: ${err instanceof Error ? err.message : err}`));
    const timer = setInterval(refresh, PREKEY_CHECK_INTERVAL_MS);
    socket.on("prekeys_low", refresh);
    return () => {
      clearInterval(timer);
      socket.off("prekeys_low", refresh);
    };
  }, [active]);

  return active;
}
