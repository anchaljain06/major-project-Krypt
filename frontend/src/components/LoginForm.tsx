import { useState } from "react";
import { db } from "../services/db";
import { deleteSessionKeyDatabase } from "../services/sessionCache";

interface LoginFormProps {
  onLogin: (
    username: string,
    password: string,
    isRegistering: boolean,
    vaultFile?: File | null,
    vaultPassword?: string,
  ) => void;
  isLoading: boolean;
}

export default function LoginForm({ onLogin, isLoading }: LoginFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [vaultFile, setVaultFile] = useState<File | null>(null);
  const [vaultPassword, setVaultPassword] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim() || isLoading) return;

    onLogin(username, password, isRegistering, vaultFile, vaultPassword);
  };

  return (
    <div
      className={`min-h-screen bg-slate-950 flex items-center justify-center p-4 ${isLoading ? "cursor-wait" : ""}`}
    >
      <div className="max-w-md w-full bg-slate-900/80 backdrop-blur-md rounded-3xl shadow-2xl overflow-hidden border border-slate-800">
        <div className="bg-linear-to-r from-indigo-600 to-indigo-800 px-8 py-10 text-center text-white">
          <h1 className="text-3xl font-extrabold tracking-tight mb-2">Krypt</h1>
          <p className="text-indigo-200 text-sm font-medium">
            Zero-Knowledge Authentication
          </p>
        </div>

        <form onSubmit={handleSubmit} className="p-8 space-y-6">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={isLoading}
              className="w-full px-4 py-3 bg-slate-950/50 border border-slate-700 text-slate-100 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all outline-none disabled:opacity-50 placeholder-slate-500"
              placeholder="Enter your alias"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isLoading}
              className="w-full px-4 py-3 bg-slate-950/50 border border-slate-700 text-slate-100 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all outline-none disabled:opacity-50 placeholder-slate-500"
              placeholder="Enter your secure password"
              required
            />
          </div>

          {!isRegistering && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Identity Vault File
                </label>
                <input
                  type="file"
                  accept=".vault"
                  onChange={(e) => setVaultFile(e.target.files?.[0] || null)}
                  disabled={isLoading}
                  className="w-full px-4 py-3 bg-slate-950/50 border border-slate-700 text-slate-100 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all outline-none disabled:opacity-50 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100"
                />
                <p className="text-xs text-slate-500 mt-1">
                  Optional. Only required if logging in from a new device.
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Vault Password{" "}
                  <span className="text-slate-500 text-xs font-normal">
                    (if encrypted)
                  </span>
                </label>
                <input
                  type="password"
                  value={vaultPassword}
                  onChange={(e) => setVaultPassword(e.target.value)}
                  disabled={isLoading}
                  className="w-full px-4 py-3 bg-slate-950/50 border border-slate-700 text-slate-100 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all outline-none disabled:opacity-50 placeholder-slate-500"
                  placeholder="Leave blank if not encrypted"
                />
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 px-4 rounded-xl shadow-lg transition-all flex justify-center items-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <>
                <svg
                  className="animate-spin h-5 w-5 text-white"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  ></circle>
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  ></path>
                </svg>
                Processing...
              </>
            ) : isRegistering ? (
              "Generate Proofs & Register"
            ) : (
              "Secure Login"
            )}
          </button>
        </form>

        <div className="px-8 pb-8 text-center flex flex-col items-center gap-3">
          <button
            onClick={() => setIsRegistering(!isRegistering)}
            disabled={isLoading}
            className="text-sm text-indigo-400 hover:text-indigo-300 font-medium transition-colors disabled:opacity-50"
          >
            {isRegistering
              ? "Already have an identity? Login."
              : "New here? Establish identity."}
          </button>
          <button
            type="button"
            onClick={async () => {
              localStorage.clear();
              sessionStorage.clear();
              try {
                await db.delete();
              } catch {
                // Database may already be gone.
              }
              try {
                // Also drop the non-extractable session key store.
                await deleteSessionKeyDatabase();
              } catch {
                // Database may already be gone.
              }
              window.location.reload();
            }}
            disabled={isLoading}
            className="text-xs text-slate-500 hover:text-red-400 transition-colors disabled:opacity-50 flex items-center gap-1"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
            Clear Browser Cache & Storage
          </button>
        </div>
      </div>
    </div>
  );
}