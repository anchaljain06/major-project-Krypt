import { useState } from "react";
import { getSuite, setSuite } from "../services/settings";

/** Settings switch for the ratchet suite of NEW sessions (plan 3.5). */
export default function SuiteToggle({ user }: { user: string }) {
  const [hybrid, setHybrid] = useState(() => getSuite(user) === "xwing");
  return (
    <label className="flex items-start gap-3 cursor-pointer select-none">
      <input
        type="checkbox"
        className="mt-0.5 accent-indigo-500"
        checked={hybrid}
        data-testid="suite-toggle"
        onChange={(e) => {
          setHybrid(e.target.checked);
          setSuite(user, e.target.checked ? "xwing" : "mlkem768");
        }}
      />
      <span>
        <span className="block text-xs font-bold text-slate-200">Hybrid ratchet (X-Wing)</span>
        <span className="block text-[11px] text-slate-400">
          New chats you start combine ML-KEM-768 with classical X25519, so they stay safe if either one breaks.
          Existing chats keep their suite.
        </span>
      </span>
    </label>
  );
}
