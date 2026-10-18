import { useSyncExternalStore } from "react";
import { getKtState, subscribeKt } from "../services/kt";
import { ktSummary, toneClass } from "./ktSummary";

/** Global key-transparency status, always visible in the sidebar header. */
export default function KtBadge() {
  const state = useSyncExternalStore(subscribeKt, getKtState);
  const { label, tone, detail } = ktSummary(state);
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full border text-[10px] font-bold uppercase tracking-wide ${toneClass[tone]}`}
      title={detail}
      data-testid="kt-badge"
    >
      {label}
    </span>
  );
}
