import React from "react";
import { validateVaultPassword, MIN_VAULT_PASSWORD_LENGTH } from "../crypto/vault";

interface SidebarProps {
  user: string;
  activeChat: string | null;
  setActiveChat: (name: string | null) => void;
  pendingRequests: string[];
  sentRequests: string[];
  friendsList: string[];
  blockedUsers: string[];
  searchResults: any[];
  searchQuery: string;
  onSearch: (query: string) => void;
  onSendRequest: (target: string) => void;
  onAcceptRequest: (target: string) => void;
  onRejectRequest: (target: string) => void;
  onBlockUser: (target: string) => void;
  onUnblockUser: (target: string) => void;
  showBlockPanel: boolean;
  setShowBlockPanel: (show: boolean) => void;
  getRelationship: (username: string) => "friend" | "sent" | "pending" | "none";
  onLogout: (
    shouldDownload: boolean,
    password: string,
    clearCache?: boolean,
  ) => void;
  onDownloadVault: (password: string) => void;
  onlineUsers: string[];
  onRevokeRequest: (target: string) => void;
  onExportChats: (password: string) => void;
  onImportChats: (file: File, password: string) => void;
  onWipeCache: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({
  user,
  activeChat,
  setActiveChat,
  pendingRequests,
  sentRequests,
  friendsList,
  blockedUsers,
  searchResults,
  searchQuery,
  onSearch,
  onSendRequest,
  onAcceptRequest,
  onRejectRequest,
  onBlockUser,
  onUnblockUser,
  showBlockPanel,
  setShowBlockPanel,
  getRelationship,
  onLogout,
  onDownloadVault,
  onlineUsers,
  onRevokeRequest,
  onExportChats,
  onImportChats,
  onWipeCache,
}) => {
  const [activeTab, setActiveTab] = React.useState<"active" | "requests">(
    "active",
  );
  const [showLogoutModal, setShowLogoutModal] = React.useState(false);
  const [showDownloadModal, setShowDownloadModal] = React.useState(false);
  const [vaultPassword, setVaultPassword] = React.useState("");
  const [vaultConfirm, setVaultConfirm] = React.useState("");
  const vaultError = validateVaultPassword(vaultPassword, vaultConfirm);
  const showVaultError =
    (vaultPassword.length > 0 || vaultConfirm.length > 0) && !!vaultError;
  const resetVaultFields = () => {
    setVaultPassword("");
    setVaultConfirm("");
  };
  const [backupOnLogout, setBackupOnLogout] = React.useState(true);
  const [clearCacheOnLogout, setClearCacheOnLogout] = React.useState(false);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  return (
    <div className="w-1/4 max-w-sm bg-slate-900 border-r border-slate-800 flex flex-col z-10">
      <div className="p-5 bg-slate-950 text-white flex justify-between items-center border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight">Krypt</h2>
          <p className="text-xs text-indigo-400 mt-1 flex items-center gap-1 font-medium">
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.6)]"></span>
            {user}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowDownloadModal(true)}
            className="p-2 hover:bg-slate-800 rounded-lg transition text-indigo-400 hover:text-indigo-300"
            title="Download Vault"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
              ></path>
            </svg>
          </button>
          <button
            onClick={() => setShowLogoutModal(true)}
            className="p-2 hover:bg-slate-800 rounded-lg transition text-red-400 hover:text-red-300"
            title="Nuclear Logout"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
              ></path>
            </svg>
          </button>
          <button
            onClick={() => setShowBlockPanel(!showBlockPanel)}
            className="p-2 hover:bg-slate-800 rounded-lg transition text-slate-400 hover:text-slate-200"
            title="Settings"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
              ></path>
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
              ></path>
            </svg>
          </button>
        </div>
      </div>

      <input
        type="file"
        accept=".cipherbackup"
        ref={fileInputRef}
        style={{ display: "none" }}
        onChange={(e) => {
          if (e.target.files && e.target.files.length > 0) {
            const file = e.target.files[0];
            const pwd = window.prompt(
              "Enter the password for this chat backup:",
            );
            if (pwd !== null) {
              onImportChats(file, pwd);
            }
          }
          e.target.value = "";
        }}
      />

      {showDownloadModal && (
        <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 w-full max-w-sm">
            <h3 className="text-lg font-bold text-slate-100 mb-2">
              Secure Vault Backup
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Choose a password to encrypt your vault file (at least{" "}
              {MIN_VAULT_PASSWORD_LENGTH} characters). Vault files are always
              encrypted; you will need this password to restore your identity.
            </p>
            <input
              type="password"
              placeholder="Vault Password"
              value={vaultPassword}
              onChange={(e) => setVaultPassword(e.target.value)}
              className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-100 mb-3 placeholder-slate-500"
            />
            <input
              type="password"
              placeholder="Confirm Vault Password"
              value={vaultConfirm}
              onChange={(e) => setVaultConfirm(e.target.value)}
              className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-100 mb-2 placeholder-slate-500"
            />
            <p className="text-xs text-red-400 min-h-4 mb-4">
              {showVaultError ? vaultError : ""}
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowDownloadModal(false);
                  resetVaultFields();
                }}
                className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (vaultError) return;
                  onDownloadVault(vaultPassword);
                  setShowDownloadModal(false);
                  resetVaultFields();
                }}
                disabled={!!vaultError}
                className="px-4 py-2 text-sm font-bold bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors shadow-md disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Download
              </button>
            </div>
          </div>
        </div>
      )}

      {showLogoutModal && (
        <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 w-full max-w-sm">
            <h3 className="text-lg font-bold text-red-400 mb-2">
              Initiate Disconnect
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Your messages will be preserved in a local encrypted cache. You
              will need your password to log back in.
            </p>
            <label className="flex items-center gap-2 mb-4 text-sm text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={backupOnLogout}
                onChange={(e) => setBackupOnLogout(e.target.checked)}
                className="w-4 h-4 rounded border-slate-700 text-indigo-600 focus:ring-indigo-500 focus:ring-offset-slate-900 bg-slate-950"
              />
              Download vault backup before logout
            </label>
            <label className="flex items-center gap-2 mb-4 text-sm text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={clearCacheOnLogout}
                onChange={(e) => setClearCacheOnLogout(e.target.checked)}
                className="w-4 h-4 rounded border-slate-700 text-red-600 focus:ring-red-500 focus:ring-offset-slate-900 bg-slate-950"
              />
              Wipe Local Device Cache (Messages)
            </label>
            {backupOnLogout && (
              <>
                <input
                  type="password"
                  placeholder={`Vault Password (min ${MIN_VAULT_PASSWORD_LENGTH} characters)`}
                  value={vaultPassword}
                  onChange={(e) => setVaultPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-100 mb-3 placeholder-slate-500"
                />
                <input
                  type="password"
                  placeholder="Confirm Vault Password"
                  value={vaultConfirm}
                  onChange={(e) => setVaultConfirm(e.target.value)}
                  className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-100 mb-2 placeholder-slate-500"
                />
                <p className="text-xs text-red-400 min-h-4 mb-4">
                  {showVaultError ? vaultError : ""}
                </p>
              </>
            )}
            <div className="flex justify-end gap-3 mt-2">
              <button
                onClick={() => {
                  setShowLogoutModal(false);
                  resetVaultFields();
                }}
                className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (backupOnLogout && vaultError) return;
                  onLogout(
                    backupOnLogout,
                    backupOnLogout ? vaultPassword : "",
                    clearCacheOnLogout,
                  );
                  setShowLogoutModal(false);
                  resetVaultFields();
                }}
                disabled={backupOnLogout && !!vaultError}
                className="px-4 py-2 text-sm font-bold bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors shadow-md flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                  ></path>
                </svg>
                Confirm Logout
              </button>
            </div>
          </div>
        </div>
      )}

      {showBlockPanel && (
        <div className="m-4 p-3 bg-slate-800 rounded-xl border border-slate-700 shadow-sm">
          <div className="flex justify-between items-center mb-2">
            <h3 className="text-xs font-bold text-red-400 uppercase tracking-wider">
              Blocked Users
            </h3>
            <button
              onClick={() => setShowBlockPanel(false)}
              className="text-slate-400 hover:text-red-400 text-xs transition-colors"
            >
              ✕
            </button>
          </div>
          {blockedUsers.length === 0 ? (
            <p className="text-xs text-slate-500 italic">No blocked users.</p>
          ) : (
            blockedUsers.map((blockedName) => (
              <div
                key={blockedName}
                className="flex justify-between items-center mb-2 bg-slate-900 p-2 rounded-lg border border-slate-700"
              >
                <span className="font-medium text-sm text-slate-300">
                  {blockedName}
                </span>
                <button
                  onClick={() => onUnblockUser(blockedName)}
                  className="px-3 py-1 bg-slate-700 text-red-400 text-xs font-bold rounded-md hover:bg-slate-600 transition"
                >
                  Unblock
                </button>
              </div>
            ))
          )}

          <div className="mt-4 pt-4 border-t border-slate-700 space-y-2">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
              Data Management
            </h3>
            <button
              onClick={() => {
                const pwd = window.prompt(
                  "Enter a password to encrypt your chat backup:",
                );
                if (pwd) onExportChats(pwd);
              }}
              className="w-full px-3 py-2 bg-slate-900 text-indigo-400 text-xs font-bold rounded-lg border border-slate-700 hover:bg-slate-700 hover:text-indigo-300 transition text-left"
            >
              Export Chat Backup (.cipherbackup)
            </button>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="w-full px-3 py-2 bg-slate-900 text-green-400 text-xs font-bold rounded-lg border border-slate-700 hover:bg-slate-700 hover:text-green-300 transition text-left"
            >
              Restore Chat Backup
            </button>
            <button
              onClick={() => {
                if (
                  window.confirm(
                    "Are you SURE you want to wipe this device's cache? All messages will be permanently deleted unless you have a backup.",
                  )
                ) {
                  onWipeCache();
                }
              }}
              className="w-full px-3 py-2 bg-red-900/30 text-red-400 text-xs font-bold rounded-lg border border-red-900/50 hover:bg-red-900/50 transition text-left"
            >
              Wipe Local Device Cache
            </button>
          </div>
        </div>
      )}

      {/* Tabbed Navigation Header */}
      <div className="flex border-b border-slate-800 bg-slate-900 mt-2">
        <button
          onClick={() => setActiveTab("active")}
          className={`flex-1 py-3 text-sm font-semibold transition-colors ${activeTab === "active" ? "text-indigo-400 border-b-2 border-indigo-500" : "text-slate-400 hover:text-slate-300"}`}
        >
          Active Link
        </button>
        <button
          onClick={() => setActiveTab("requests")}
          className={`flex-1 py-3 text-sm font-semibold transition-colors flex justify-center items-center gap-2 ${activeTab === "requests" ? "text-indigo-400 border-b-2 border-indigo-500" : "text-slate-400 hover:text-slate-300"}`}
        >
          Requests
          {(pendingRequests.length > 0 || sentRequests.length > 0) && (
            <span className="bg-amber-500 text-slate-900 text-[10px] px-1.5 py-0.5 rounded-full">
              {pendingRequests.length + sentRequests.length}
            </span>
          )}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto bg-slate-900 flex flex-col">
        {activeTab === "requests" && (
          <div className="p-4 flex-1">
            <div className="mb-4">
              <input
                type="text"
                placeholder="Search global network..."
                value={searchQuery}
                onChange={(e) => onSearch(e.target.value)}
                className="w-full px-4 py-2 bg-slate-950 border border-slate-800 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm text-slate-200 transition-all placeholder-slate-600"
              />

              {searchResults.length > 0 && (
                <div className="mt-2 bg-slate-800 border border-slate-700 rounded-lg shadow-xl overflow-hidden">
                  {searchResults.map((result) => {
                    const rel = getRelationship(result.username);
                    return (
                      <div
                        key={result.username}
                        className="flex justify-between items-center p-3 hover:bg-slate-700 border-b border-slate-700 last:border-0 transition-colors"
                      >
                        <span className="text-sm font-medium text-slate-200">
                          {result.username}
                        </span>
                        {rel === "friend" ? (
                          <span className="text-xs text-green-400 font-medium px-2 py-1 bg-green-400/10 rounded-md">
                            ✓ Friends
                          </span>
                        ) : rel === "sent" ? (
                          <span className="text-xs text-amber-500 font-medium px-2 py-1 bg-amber-500/10 rounded-md">
                            Pending...
                          </span>
                        ) : rel === "pending" ? (
                          <button
                            onClick={() => onAcceptRequest(result.username)}
                            className="text-xs bg-indigo-600 text-white px-3 py-1.5 rounded-md hover:bg-indigo-500 transition font-medium"
                          >
                            Accept
                          </button>
                        ) : (
                          <button
                            onClick={() => onSendRequest(result.username)}
                            className="text-xs bg-slate-600 text-white px-3 py-1.5 rounded-md hover:bg-slate-500 transition font-medium"
                          >
                            Invite
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {pendingRequests.length > 0 && (
              <div className="mb-4 p-3 bg-slate-800 rounded-xl border border-slate-700 shadow-sm">
                <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-wider mb-2">
                  Incoming Requests
                </h3>
                {pendingRequests.map((requester) => (
                  <div
                    key={requester}
                    className="flex justify-between items-center mb-2 bg-slate-900 p-2 rounded-lg border border-slate-700"
                  >
                    <span className="font-medium text-sm text-slate-300">
                      {requester}
                    </span>
                    <div className="flex gap-1">
                      <button
                        onClick={() => onAcceptRequest(requester)}
                        className="px-2 py-1 bg-indigo-600 text-white text-xs font-bold rounded-md hover:bg-indigo-500 transition"
                      >
                        Accept
                      </button>
                      <button
                        onClick={() => onRejectRequest(requester)}
                        className="px-2 py-1 bg-slate-700 text-white text-xs font-bold rounded-md hover:bg-slate-600 transition"
                      >
                        Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {sentRequests.length > 0 && (
              <div className="mb-4 p-3 bg-slate-800 rounded-xl border border-slate-700 shadow-sm">
                <h3 className="text-xs font-bold text-amber-500 uppercase tracking-wider mb-2">
                  Awaiting Response
                </h3>
                {sentRequests.map((target) => (
                  <div
                    key={target}
                    className="flex justify-between items-center mb-2 bg-slate-900 p-2 rounded-lg border border-slate-700"
                  >
                    <span className="font-medium text-sm text-slate-300">
                      {target}
                    </span>
                    <div className="flex gap-1">
                      <span className="text-xs text-amber-500 font-medium px-2 py-1 bg-amber-500/10 rounded-md">
                        Pending
                      </span>
                      <button
                        onClick={() => onRevokeRequest(target)}
                        className="px-2 py-1 bg-red-900/30 text-red-400 text-[10px] font-bold rounded-md hover:bg-red-900/50 transition border border-red-900/50"
                      >
                        Revoke
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === "active" && (
          <div className="p-2 flex-1">
            {friendsList.length > 0 ? (
              <div className="space-y-1">
                <p className="px-3 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  Secure Channels
                </p>
                {friendsList.map((chatUsername) => {
                  const isOnline = onlineUsers.includes(chatUsername);
                  return (
                    <div
                      key={chatUsername}
                      className="group flex items-center gap-0"
                    >
                      <button
                        onClick={() => setActiveChat(chatUsername)}
                        className={`flex-1 text-left px-4 py-3 rounded-lg transition-colors flex items-center gap-3 relative ${
                          activeChat === chatUsername
                            ? "bg-slate-800 border border-slate-700 shadow-sm"
                            : "hover:bg-slate-800/50 border border-transparent"
                        }`}
                      >
                        <div className="relative">
                          <div className="h-10 w-10 bg-slate-700 text-slate-300 border border-slate-600 rounded-full flex items-center justify-center font-bold text-lg shrink-0 shadow-inner">
                            {chatUsername.charAt(0).toUpperCase()}
                          </div>
                          {isOnline && (
                            <div className="absolute bottom-0 right-0 w-3 h-3 bg-green-500 rounded-full border-2 border-slate-900"></div>
                          )}
                        </div>
                        <div className="min-w-0">
                          <p
                            className={`font-medium truncate ${activeChat === chatUsername ? "text-indigo-400" : "text-slate-300"}`}
                          >
                            {chatUsername}
                          </p>
                          <p
                            className={`text-[10px] font-medium uppercase tracking-wider ${isOnline ? "text-green-500/80" : "text-slate-500"}`}
                          >
                            {isOnline ? "Encrypted Link Active" : "Offline"}
                          </p>
                        </div>
                      </button>
                      <button
                        onClick={() => onBlockUser(chatUsername)}
                        className="opacity-0 group-hover:opacity-100 p-1.5 text-slate-500 hover:text-red-400 transition-all mr-1 shrink-0"
                        title={`Block ${chatUsername}`}
                      >
                        <svg
                          className="w-4 h-4"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth="2"
                            d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
                          ></path>
                        </svg>
                      </button>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 p-8 text-center">
                <svg
                  className="w-10 h-10 mb-3 text-slate-700"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="1.5"
                    d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
                  ></path>
                </svg>
                <p className="text-sm">
                  Switch to the Requests tab to find users and establish a
                  connection.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Sidebar;