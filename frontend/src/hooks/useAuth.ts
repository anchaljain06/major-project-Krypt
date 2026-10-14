import { useState, useEffect } from "react";
import { socket } from "../services/socket";
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
} from "../crypto/vault";

export function useAuth() {
  const [user, setUser] = useState(localStorage.getItem("currentUser") || "");
  const [myPrivateKey, setMyPrivateKey] = useState<UserIdentityKeys | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Auto-restore private identity keys from encrypted cache on page refresh
  useEffect(() => {
    if (!user || myPrivateKey) return;
    const restoreKey = async () => {
      const cachedPassword = sessionStorage.getItem("sessionPassword");
      const cachedKey = localStorage.getItem(`encryptedPrivateKey_${user}`);
      if (!cachedPassword || !cachedKey) return;
      try {
        const decryptedPrivateStr = await decryptVaultData(
          cachedKey,
          cachedPassword,
        );
        const loadedKeys = importPrivateIdentity(decryptedPrivateStr);
        setMyPrivateKey(loadedKeys);
      } catch (err) {
        sessionStorage.removeItem("sessionPassword");
        // No toast here to avoid annoying the user on every fresh load if they aren't logged in
      }
    };
    restoreKey();
  }, [user]);

  const handleLogin = async (
    username: string,
    password: string,
    isRegistering: boolean,
    vaultFile?: File | null,
    vaultPassword?: string,
  ) => {
    setIsLoading(true);
    try {
      if (isRegistering) {
        const salt = srp.generateSalt();
        const privateKey = srp.derivePrivateKey(salt, username, password);
        const verifier = srp.deriveVerifier(privateKey);

        const keys = generateUserIdentityKeys();
        const publicKeyStr = exportPublicIdentity(keys);

        const res = await fetch(
          `${import.meta.env.VITE_API_URL}/api/register`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username,
              publicKey: publicKeyStr,
              srpSalt: salt,
              srpVerifier: verifier,
            }),
          },
        );

        if (!res.ok) {
          const data = await res.json();
          throw new Error(
            data.error || "Registration failed. Username might be taken.",
          );
        }

        setMyPrivateKey(keys);
        const privateKeyStr = exportPrivateIdentity(keys);
        // Securely cache the private identity key for returning logins
        const encryptedCache = await encryptVaultData(
          privateKeyStr,
          password,
        );
        localStorage.setItem(`encryptedPrivateKey_${username}`, encryptedCache);

        // Vault Birth: Do not download automatically anymore.
        // User must click Download Vault in the UI.
      } else {
        const clientEphemeral = srp.generateEphemeral();
        const challengeRes = await fetch(
          `${import.meta.env.VITE_API_URL}/api/login/challenge`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username,
              clientEphemeralPublic: clientEphemeral.public,
            }),
          },
        );

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

        const verifyRes = await fetch(
          `${import.meta.env.VITE_API_URL}/api/login/verify`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username,
              clientEphemeralPublic: clientEphemeral.public,
              clientSessionProof: clientSession.proof,
            }),
          },
        );

        if (!verifyRes.ok) {
          const data = await verifyRes.json();
          throw new Error(data.error || "Invalid password!");
        }

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
          } catch (err) {
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
          } catch (err) {
            throw new Error(
              "Failed to decrypt vault file. Check your vault password.",
            );
          }

          let vault;
          try {
            vault = JSON.parse(decryptedContent);
          } catch (err) {
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
              (c: any) => c.id && c.payload,
            );
            if (validContacts.length > 0) {
              await db.contacts.bulkAdd(validContacts);
            }
          }
        }

        const loadedKeys = importPrivateIdentity(privateKeyStrToImport);
        setMyPrivateKey(loadedKeys);
      }

      localStorage.setItem("currentUser", username);
      sessionStorage.setItem("sessionPassword", password);
      setUser(username);
      socket.connect();
    } catch (err: any) {
      console.error("Login Error:", err);
      toast.error(err?.message || "An unknown error occurred during login.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!user || !myPrivateKey) return;

    const onConnect = () => {
      socket.emit("register_socket", user);
    };

    if (socket.connected) {
      onConnect();
    }

    socket.on("connect", onConnect);
    socket.connect();

    return () => {
      socket.off("connect", onConnect);
    };
  }, [user, myPrivateKey]);

  const handleDownloadVault = async (vaultPassword?: string) => {
    if (!myPrivateKey || !user) return;
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
      toast.success("Vault downloaded securely.");
    } catch (err: any) {
      toast.error("Failed to download vault: " + err.message);
    }
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
    } catch (err: any) {
      toast.error("Failed to backup chats: " + err.message);
    }
  };

  const handleImportChats = async (file: File, password: string) => {
    try {
      const content = await file.text();
      await importChatBackup(content, password);
      toast.success("Chat history restored successfully.");
    } catch (err: any) {
      toast.error("Failed to restore chats: " + err.message);
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
    } catch (err: any) {
      toast.error("Failed to wipe cache: " + err.message);
    }
  };

  const handleLogout = async (
    shouldDownload: boolean = false,
    vaultPassword?: string,
    clearCache: boolean = false,
  ) => {
    if (!myPrivateKey || !user) return;

    if (shouldDownload) {
      await handleDownloadVault(vaultPassword);
      await new Promise((resolve) => setTimeout(resolve, 1500)); // Ensure download begins before reload
    }

    if (clearCache) {
      await db.messages.clear();
      await db.contacts.clear();
    }

    // Secure sign out
    localStorage.removeItem("currentUser");
    sessionStorage.removeItem("sessionPassword");
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
    handleExportChats,
    handleImportChats,
    handleWipeCache,
    isLoading,
  };
}
