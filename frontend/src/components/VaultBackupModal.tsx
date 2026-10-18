import { useState } from "react";
import { validateVaultPassword, MIN_VAULT_PASSWORD_LENGTH } from "../crypto/vault";

interface VaultBackupModalProps {
  user: string;
  onDownload: (password: string) => Promise<boolean>;
  onContinue: () => void;
}

/**
 * Blocking screen shown right after registration. The chat dashboard stays
 * hidden until the user has downloaded an encrypted .vault file, because the
 * private identity key exists nowhere else.
 */
export default function VaultBackupModal({
  user,
  onDownload,
  onContinue,
}: VaultBackupModalProps) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [isBusy, setIsBusy] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  const validationError = validateVaultPassword(password, confirm);
  const showError = (password.length > 0 || confirm.length > 0) && validationError;

  const handleDownload = async () => {
    if (validationError || isBusy) return;
    setIsBusy(true);
    const ok = await onDownload(password);
    setIsBusy(false);
    if (ok) {
      setDownloaded(true);
      setPassword("");
      setConfirm("");
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="vault-backup-title"
        className="max-w-md w-full bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6"
      >
        <h3
          id="vault-backup-title"
          className="text-lg font-bold text-slate-100 mb-2"
        >
          Back up your identity vault
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Welcome, <span className="text-indigo-400 font-medium">{user}</span>.
          Your private identity key exists only in this browser. Download an
          encrypted vault file now: you need it to log in on another device or
          after clearing this browser. Nobody, including the server, can
          recover it for you.
        </p>

        {!downloaded ? (
          <>
            <input
              type="password"
              placeholder={`Vault password (min ${MIN_VAULT_PASSWORD_LENGTH} characters)`}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isBusy}
              autoFocus
              className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-100 mb-3 placeholder-slate-500 disabled:opacity-50"
            />
            <input
              type="password"
              placeholder="Confirm vault password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={isBusy}
              className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-100 mb-2 placeholder-slate-500 disabled:opacity-50"
            />
            <p className="text-xs text-red-400 min-h-4 mb-4">
              {showError ? validationError : ""}
            </p>
            <div className="flex justify-end">
              <button
                onClick={handleDownload}
                disabled={!!validationError || isBusy}
                className="px-4 py-2 text-sm font-bold bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors shadow-md disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isBusy ? "Encrypting..." : "Download Encrypted Vault"}
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="text-sm text-green-400 mb-4">
              Vault downloaded. Store it somewhere safe and remember its
              password. If the download did not start, download it again.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDownloaded(false)}
                className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200"
              >
                Download again
              </button>
              <button
                onClick={onContinue}
                className="px-4 py-2 text-sm font-bold bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors shadow-md"
              >
                I saved it, continue
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
