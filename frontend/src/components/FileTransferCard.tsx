import React, { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import toast from "react-hot-toast";
import { formatBytes } from "../crypto/media";
import { filesFor, type FileCardInfo } from "../services/messaging";
import type { FileTransferManager } from "../services/fileTransfer";
import { protocolReady } from "../services/protocol";

const noop = () => () => {};

/** Live view of one transfer from the FileTransferManager. */
function useTransfer(id: string) {
  const [m, setM] = useState<FileTransferManager | null>(null);
  useEffect(() => {
    let live = true;
    void protocolReady().then(async (p) => {
      const mgr = filesFor(p);
      await mgr.whenReady();
      if (live) setM(mgr);
    });
    return () => {
      live = false;
    };
  }, []);
  const subscribe = useCallback((fn: () => void) => (m ? m.subscribe(fn) : noop()), [m]);
  const v = useSyncExternalStore(subscribe, () => m?.get(id));
  return { m, v };
}

const STATUS_TEXT: Record<string, string> = {
  offered: "Waiting for a reply",
  sending: "Sending",
  paused: "Paused",
  receiving: "Receiving",
  complete: "Done",
  cancelled: "Cancelled",
  expired: "Expired",
  gone: "No longer on this device",
  loading: "…",
};

/**
 * A file transfer in the chat. Nothing is opened or previewed: the only way to
 * get the file is the explicit Download button, which saves it under a cleaned
 * name as application/octet-stream.
 */
const FileTransferCard: React.FC<{ info: FileCardInfo }> = ({ info }) => {
  const { m, v } = useTransfer(info.transferId);
  const [busy, setBusy] = useState(false);
  const run = (fn: () => Promise<void>) => async () => {
    setBusy(true);
    try {
      await fn();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "File transfer failed.");
    } finally {
      setBusy(false);
    }
  };
  const download = run(async () => {
    const { blob, name } = await m!.download(info.transferId);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.rel = "noopener";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  });

  const status = v?.status ?? (m ? "gone" : "loading");
  const pct = v && v.chunkCount > 0 ? Math.round((100 * v.done) / v.chunkCount) : 0;
  const active = status === "sending" || status === "receiving" || status === "paused";
  const btn = "px-2 py-1 text-xs font-semibold rounded-lg border transition disabled:opacity-50";

  return (
    <div data-testid="file-transfer" data-status={status} className="text-sm px-1 py-1 min-w-56 space-y-1">
      <p className="font-semibold break-all">{info.name}</p>
      <p className="text-xs opacity-80">
        {formatBytes(info.size)} · {STATUS_TEXT[status] ?? status}
        {active ? ` · ${pct}%` : ""}
      </p>
      {v?.note && <p className="text-xs opacity-80">{v.note}</p>}
      {active && (
        <div className="h-1.5 rounded bg-slate-950/40 overflow-hidden">
          <div className="h-full bg-emerald-400" style={{ width: `${pct}%` }} />
        </div>
      )}
      <div className="flex gap-2 pt-1">
        {v?.direction === "in" && status === "offered" && (
          <>
            <button type="button" disabled={busy} onClick={run(() => m!.accept(info.transferId))} className={`${btn} bg-emerald-700 border-emerald-600`}>
              Accept file
            </button>
            <button type="button" disabled={busy} onClick={run(() => m!.reject(info.transferId))} className={`${btn} bg-slate-700 border-slate-600`}>
              Decline
            </button>
          </>
        )}
        {(active || (v?.direction === "out" && status === "offered")) && (
          <button type="button" disabled={busy} onClick={run(() => m!.cancel(info.transferId))} className={`${btn} bg-slate-700 border-slate-600`}>
            Cancel
          </button>
        )}
        {v?.direction === "in" && status === "complete" && (
          <button type="button" disabled={busy} onClick={download} className={`${btn} bg-indigo-700 border-indigo-600`}>
            Download
          </button>
        )}
      </div>
    </div>
  );
};

export default FileTransferCard;
