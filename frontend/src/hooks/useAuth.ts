import { useState, useEffect } from "react";
import { socket, connectSocket, disconnectSocket } from "../services/socket";
import { apiPostJson, setUnauthorizedHandler, notifyUnauthorized } from "../services/api";
import { getToken, setToken, clearToken } from "../services/authToken";
import {
  createSessionCache,
  restoreSessionCache,
  clearSessionCache,
} from "../services/sessionCache";
import {
  generateUserIdentityKeys,
  exportPublicIdentity,
  exportPrivateIdentity,
  importPrivateIdentity,
  type UserIdentityKeys,
} from "../crypto/mlkem";
import srp from "secure-remote-password/client";
import toast from "react-hot-toast";
import { db } from "../services/db";
import {
  encryptVaultData,
  decryptVaultData,
  exportChatBackup,
  importChatBackup,
  MIN_VAULT_PASSWORD_LENGTH,
} from "../crypto/vault";

// sessionStorage key for a one-shot message shown after a forced reload
const FLASH_KEY = "krypt_flash";

// localStorage marker: account registered here but no encrypted vault downloaded yet
const vaultPendingKey = (username: string) => `vaultPending_${username}`;

const errorMessage = (err: unknown) =>
  err instanceof Error ? err.message : "Unknown error";

/**
 * Ends the server session after the token was rejected (REST 401 or socket
 * "unauthorized"): drop the token and socket, then reload into the login screen.
 */
let isExpiring = false;
async function expireSession() {
  if (isExpiring) return;
  isExpiring = true;
  clearToken();
  disconnectSocket();
  await clearSessionCache().catch(() => {});
  localStorage.removeItem("currentUser");
  sessionStorage.setItem(FLASH_KEY, "Session expired. Please log in again.");
  window.location.reload();
}

export function useAuth() {
  const [user, setUser] = useState(localStorage.getItem("currentUser") || "");
  const [myPrivateKey, setMyPrivateKey] = useState<UserIdentityKeys | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  // True until a freshly registered user has downloaded an encrypted vault
  const [needsVaultBackup, setNeedsVaultBackup] = useState(() => {
    const current = localStorage.getItem("currentUser");
    return !!current && !!localStorage.getItem(vaultPendingKey(current));
  });

  // Route every token rejection (REST or socket) to the same logout path.
  useEffect(() => {
    const flash = sessionStorage.getItem(FLASH_KEY);
    if (flash) {
      sessionStorage.removeItem(FLASH_KEY);
      toast.error(flash);
    }

    setUnauthorizedHandler(expireSession);
    const onConnectError = (err: Error) => {
      if (err?.message === "unauthorized") notifyUnauthorized();
    };
    socket.on("connect_error", onConnectError);
    return () => {
      setUnauthorizedHandler(null);
      socket.off("connect_error", onConnectError);
    };
  }, []);

  // Auto-restore private identity keys on page refresh within the same tab.
  // Uses the non-extractable session key (services/sessionCache.ts); never a password.
  useEffect(() => {
    // Migration: older builds kept the plaintext login password here.
    sessionStorage.removeItem("sessionPassword");

    if (!user || myPrivateKey) return;
    let cancelled = false;
    const restoreKey = async () => {
      if (!getToken()) {
        // No server session in this tab: drop any leftover cache, require login.
        await clearSessionCache().catch(() => {});
        return;
      }
      try {
        const bundle = await restoreSessionCache(user);
        if (!bundle || cancelled) return;
        setMyPrivateKey(importPrivateIdentity(bundle));
      } catch {
        await clearSessionCache(user).catch(() => {});
        // No toast here to avoid annoying the user on every fresh load if they aren't logged in
      }
    };
    restoreKey();
    return () => {
      cancelled = true;
    };
  }, [user, myPrivateKey]);

  const handleLogin = async (
    username: string,
    password: string,
    isRegistering: boolean,
    vaultFile?: File | null,
    vaultPassword?: string,
  ) => {
    setIsLoading(true);
    // Any previous session token is discarded; login/registration run unauthenticated.
    clearToken();
    let sessionToken = "";
    let loadedKeys: UserIdentityKeys;
    let privateKeyBundle: string;
    try {
      if (isRegistering) {
        const salt = srp.generateSalt();
        const privateKey = srp.derivePrivateKey(salt, username, password);
        const verifier = srp.deriveVerifier(privateKey);

        const keys = generateUserIdentityKeys();
        const publicKeyStr = exportPublicIdentity(keys);

        const res = await apiPostJson("/api/register", {
          username,
          publicKey: publicKeyStr,
          srpSalt: salt,
          srpVerifier: verifier,
        });

        const registerData = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(
            registerData.error || "Registration failed. Username might be taken.",
          );
        }
        if (typeof registerData.token !== "string" || !registerData.token) {
          throw new Error("Registration failed: server did not issue a session.");
        }
        sessionToken = registerData.token;

        loadedKeys = keys;
        privateKeyBundle = exportPrivateIdentity(keys);
        // Password-encrypted copy for returning logins on this device
        const encryptedCache = await encryptVaultData(
          privateKeyBundle,
          password,
        );
        localStorage.setItem(`encryptedPrivateKey_${username}`, encryptedCache);

        // Vault birth: the dashboard stays locked until an encrypted vault is downloaded.
        localStorage.setItem(vaultPendingKey(username), "1");
      } else {
        const clientEphemeral = srp.generateEphemeral();
        const challengeRes = await apiPostJson("/api/login/challenge", {
          username,
          clientEphemeralPublic: clientEphemeral.public,
        });

        if (!challengeRes.ok) {
          const data = await challengeRes.json();
          throw new Error(data.error || "Login failed: User not found.");
        }
        const { salt, serverEphemeralPublic } = await challengeRes.json();

        const privateKey = srp.derivePrivateKey(salt, username, password);
        const clientSession = srp.deriveSession(
          clientEphemeral.secret,
          serverEphemeralPublic,
          salt,
          username,
          privateKey,
        );

        const verifyRes = await apiPostJson("/api/login/verify", {
          username,
          clientEphemeralPublic: clientEphemeral.public,
          clientSessionProof: clientSession.proof,
        });

        const verifyData = await verifyRes.json().catch(() => ({}));
        if (!verifyRes.ok) {
          throw new Error(verifyData.error || "Invalid password!");
        }

        // SRP-6a mutual authentication: the server must prove (M2) that it knows
        // the verifier for this account. Without this check an impostor server
        // could accept any password. verifySession throws on mismatch.
        if (typeof verifyData.serverProof !== "string" || !verifyData.serverProof) {
          throw new Error("Login aborted: server did not prove its identity.");
        }
        try {
          srp.verifySession(
            clientEphemeral.public,
            clientSession,
            verifyData.serverProof,
          );
        } catch {
          throw new Error("Login aborted: server proof is invalid.");
        }

        if (typeof verifyData.token !== "string" || !verifyData.token) {
          throw new Error("Login failed: server did not issue a session.");
        }
        sessionToken = verifyData.token;

        // If vaultFile is missing, try to load from secure cache
        let privateKeyStrToImport = "";

        if (!vaultFile) {
          const cachedKey = localStorage.getItem(
            `encryptedPrivateKey_${username}`,
          );
          if (!cachedKey) {
            throw new Error(
              "Vault file is required when logging into a new device.",
            );
          }
          try {
            privateKeyStrToImport = await decryptVaultData(
              cachedKey,
              password,
            );
          } catch {
            throw new Error(
              "Wrong password! Could not decrypt your local security cache.",
            );
          }
        } else {
          // Vault Login Checkpoint: Extract Private Key and Contacts
          const fileContent = await vaultFile.text();
          let decryptedContent;
          try {
            decryptedContent = await decryptVaultData(
              fileContent,
              vaultPassword,
            );
          } catch {
            throw new Error(
              "Failed to decrypt vault file. Check your vault password.",
            );
          }

          let vault;
          try {
            vault = JSON.parse(decryptedContent);
          } catch {
            throw new Error("Invalid vault file format.");
          }

          if (!vault.privateKey) {
            throw new Error("Invalid vault file: Missing identity key.");
          }
          privateKeyStrToImport = vault.privateKey;

          // Securely cache the newly imported private key
          const encryptedCache = await encryptVaultData(
            privateKeyStrToImport,
            password,
          );
          localStorage.setItem(
            `encryptedPrivateKey_${username}`,
            encryptedCache,
          );

          if (vault.contacts && Array.isArray(vault.contacts)) {
            await db.contacts.clear();
            const validContacts = vault.contacts.filter(
              (c: { id?: string; payload?: string }) => c.id && c.payload,
            );
            if (validContacts.length > 0) {
              await db.contacts.bulkAdd(validContacts);
            }
          }
        }

        loadedKeys = importPrivateIdentity(privateKeyStrToImport);
        privateKeyBundle = privateKeyStrToImport;
      }

      setToken(sessionToken);
      localStorage.setItem("currentUser", username);
      try {
        // Lets a refresh in this tab resume without the password (see sessionCache.ts).
        await createSessionCache(username, privateKeyBundle);
      } catch (cacheErr) {
        console.warn("Session cache unavailable; refresh will require login.", cacheErr);
      }
      // Set together so the socket only connects once the token is in place.
      setNeedsVaultBackup(!!localStorage.getItem(vaultPendingKey(username)));
      setMyPrivateKey(loadedKeys);
      setUser(username);
    } catch (err) {
      console.error("Login Error:", err);
      toast.error(
        err instanceof Error && err.message
          ? err.message
          : "An unknown error occurred during login.",
      );
    } finally {
      setIsLoading(false);
    }
  };

  // Connect the socket once keys are loaded (after login, registration or restore).
  // The server binds the socket to the user from the token; no register_socket emit.
  useEffect(() => {
    if (!user || !myPrivateKey) return;
    const token = getToken();
    if (!token) {
      notifyUnauthorized();
      return;
    }
    connectSocket(token);
  }, [user, myPrivateKey]);

  /**
   * Downloads the identity vault, always encrypted under `vaultPassword`.
   * @returns true if the file was produced and handed to the browser
   */
  const handleDownloadVault = async (vaultPassword: string): Promise<boolean> => {
    if (!myPrivateKey || !user) return false;
    if (!vaultPassword || vaultPassword.length < MIN_VAULT_PASSWORD_LENGTH) {
      toast.error(
        `Vault password must be at least ${MIN_VAULT_PASSWORD_LENGTH} characters.`,
      );
      return false;
    }
    try {
      const privateKeyStr = exportPrivateIdentity(myPrivateKey);
      const contacts = await db.contacts.toArray();
      const vaultData = JSON.stringify({
        privateKey: privateKeyStr,
        contacts,
      });

      const encryptedData = await encryptVaultData(vaultData, vaultPassword);

      const blob = new Blob([encryptedData], {
        type: "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cipher_vault_${user}.vault`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      // The registration-time backup requirement is satisfied.
      localStorage.removeItem(vaultPendingKey(user));
      toast.success("Encrypted vault downloaded.");
      return true;
    } catch (err) {
      toast.error("Failed to download vault: " + errorMessage(err));
      return false;
    }
  };

  // Called when the user leaves the post-registration vault backup screen.
  const confirmVaultBackup = () => {
    if (user && localStorage.getItem(vaultPendingKey(user))) return;
    setNeedsVaultBackup(false);
  };

  const handleExportChats = async (password: string) => {
    try {
      if (!user) return;
      const backupString = await exportChatBackup(password);
      const blob = new Blob([backupString], {
        type: "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cipher_chats_${user}.cipherbackup`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success("Chat history backed up securely.");
    } catch (err) {
      toast.error("Failed to backup chats: " + errorMessage(err));
    }
  };

  const handleImportChats = async (file: File, password: string) => {
    try {
      const content = await file.text();
      await importChatBackup(content, password);
      toast.success("Chat history restored successfully.");
    } catch (err) {
      toast.error("Failed to restore chats: " + errorMessage(err));
    }
  };

  const handleWipeCache = async () => {
    try {
      await db.messages.clear();
      await db.contacts.clear();
      // Wipe ratchet session state
      const keysToRemove = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(`session_${user}_`)) {
          keysToRemove.push(key);
        }
      }
      for (const key of keysToRemove) {
        localStorage.removeItem(key);
      }

      toast.success("Local cache completely wiped.");
      setTimeout(() => window.location.reload(), 1500);
    } catch (err) {
      toast.error("Failed to wipe cache: " + errorMessage(err));
    }
  };

  const handleLogout = async (
    shouldDownload: boolean = false,
    vaultPassword: string = "",
    clearCache: boolean = false,
  ) => {
    if (!myPrivateKey || !user) return;

    if (shouldDownload) {
      // Do not sign out if the requested backup could not be produced.
      if (!(await handleDownloadVault(vaultPassword))) return;
      await new Promise((resolve) => setTimeout(resolve, 1500)); // Ensure download begins before reload
    }

    if (clearCache) {
      await db.messages.clear();
      await db.contacts.clear();
    }

    // Secure sign out
    disconnectSocket();
    clearToken();
    await clearSessionCache(user).catch(() => {});
    localStorage.removeItem("currentUser");
    setMyPrivateKey(null);
    setUser("");
    window.location.reload();
  };

  return {
    user,
    setUser,
    myPrivateKey,
    setMyPrivateKey,
    handleLogin,
    handleLogout,
    handleDownloadVault,
    needsVaultBackup,
    confirmVaultBackup,
    handleExportChats,
    handleImportChats,
    handleWipeCache,
    isLoading,
  };
}
