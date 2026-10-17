import type { KtGlobalState, KtPeerState } from "../services/kt";

export type Tone = "ok" | "warn" | "alert" | "muted";

export const toneClass: Record<Tone, string> = {
  ok: "bg-emerald-900/40 text-emerald-300 border-emerald-700/60",
  warn: "bg-amber-900/40 text-amber-300 border-amber-700/60",
  alert: "bg-red-900/60 text-red-200 border-red-600 animate-pulse",
  muted: "bg-slate-800 text-slate-400 border-slate-700",
};

export function ktSummary(s: KtGlobalState): { label: string; tone: Tone; detail: string } {
  switch (s.mode) {
    case "disabled":
      return {
        label: "KT disabled",
        tone: "warn",
        detail: "Key transparency is off in this build (VITE_KT_LOG_PUBKEY unset). Identity keys are trusted on first use only.",
      };
    case "pending":
      return { label: "KT checking", tone: "muted", detail: "Checking the key transparency log…" };
    case "ok":
      return {
        label: "KT verified",
        tone: "ok",
        detail:
          `Log consistent at size ${s.treeSize}. ` +
          (s.self === "logged"
            ? "Your key is in the log. "
            : "Your key is not in a published tree head yet (heads appear within about 5 minutes). ") +
          (s.witness === "verified" ? "Witness agrees." : s.witness === "stale" ? "Witness head is stale." : "No witness configured."),
      };
    case "unavailable":
      return { label: "KT unavailable", tone: "warn", detail: s.reason };
    case "error":
      return { label: "KT error", tone: "warn", detail: s.reason };
    case "alert":
      return { label: "KT ALERT", tone: "alert", detail: s.reason };
  }
}

export function ktPeerSummary(s: KtPeerState): { label: string; tone: Tone; detail: string } {
  switch (s.state) {
    case "disabled":
      return { label: "Disabled", tone: "warn", detail: "Key transparency is off in this build; the key is pinned on first use only." };
    case "verified":
      return {
        label: "Verified",
        tone: "ok",
        detail: `Key version ${s.keyVersion} is in the log (tree size ${s.treeSize}), checked ${new Date(s.at).toLocaleString()}.`,
      };
    case "not-in-log":
      return {
        label: "Not in log",
        tone: "warn",
        detail: "The log has no entry for this user yet (new or legacy account, or a tree head not published yet). Pinned on first use.",
      };
    case "error":
      return { label: "Not checked", tone: "muted", detail: s.reason };
    case "alert":
      return { label: "ALERT", tone: "alert", detail: s.reason };
  }
}
