import { useCallback } from "react";
import { socket } from "../services/socket";
import {
  importPublicIdentity,
  encapsulateSharedKey,
  decapsulateSharedKey,
  signHandshakePayload,
  verifyHandshakeSignature,
  type UserIdentityKeys,
} from "../crypto/mlkem";
import { db } from "../services/db";
import { encryptLocal, decryptLocal } from "../crypto/localStore";
import { sha256Hex } from "../crypto/utils";

export interface RatchetResult {
  key: string;
  eph?: string;
  kemCiphertext?: string;
  sig?: string;
  isHandshakeCollision?: boolean;
}

export function useRatchet(user: string, myPrivateKey: UserIdentityKeys | null) {
  const getOrCreateSessionKey = useCallback(
    async (
      targetUsername: string,
      remoteKemCiphertext?: string,
      remoteSig?: string,
    ): Promise<RatchetResult> => {
      if (!user || !myPrivateKey) throw new Error("Auth state missing");

      // 1. Check if we already have a ratcheted key for this user
      const savedKey = localStorage.getItem(
        `session_${user}_${targetUsername}`,
      );

      // If we are NOT receiving a handshake (no remoteKemCiphertext), just return the saved key
      if (savedKey && !remoteKemCiphertext) return { key: savedKey };

      // 2. If not, we must perform the ML-KEM-1024 Handshake!
      const response = await new Promise<any>((resolve) =>
        socket.emit("request_public_key", targetUsername, resolve),
      );

      if (!response.success)
        throw new Error("Could not fetch target public key.");

      const serverPublicKeyStr = response.publicKey;

      // 3. Security Firewall (TOFU - Trust On First Use) via NIST FIPS 180-4 SHA-256
      const hashedUsername = await sha256Hex(targetUsername);
      const existingContact = await db.contacts.get(hashedUsername);
      if (existingContact) {
        let contactObj: any = {};
        try {
          const jsonStr = await decryptLocal(
            existingContact.payload,
            myPrivateKey,
          );
          contactObj = JSON.parse(jsonStr);
        } catch (e) {
          // Fallback if legacy or corrupt
        }
        if (
          contactObj.publicKey &&
          contactObj.publicKey !== serverPublicKeyStr
        ) {
          throw new Error(
            "CRITICAL SECURITY ALERT: Target's public key has changed. Possible Man-in-the-Middle attack!",
          );
        }
      } else {
        const contactObj = {
          username: targetUsername,
          publicKey: serverPublicKeyStr,
        };
        await db.contacts.add({
          id: hashedUsername,
          payload: await encryptLocal(JSON.stringify(contactObj), myPrivateKey),
        });
      }

      const theirPublicIdentity = importPublicIdentity(serverPublicKeyStr);

      if (remoteKemCiphertext && remoteSig) {
        // RECEIVER
        // 1. Verify ML-DSA-87 signature (NIST FIPS 204) to ensure sender authenticity
        const isSigValid = verifyHandshakeSignature(
          targetUsername,
          user,
          remoteKemCiphertext,
          remoteSig,
          theirPublicIdentity.dsaPublicKey,
        );
        if (!isSigValid) {
          throw new Error(
            "Handshake Security Failure: ML-KEM-1024 handshake signature mismatch!",
          );
        }

        // 2. Decapsulate the ML-KEM-1024 ciphertext to obtain the root AES-256 session key
        const rootBase64 = await decapsulateSharedKey(
          remoteKemCiphertext,
          myPrivateKey.kemSecretKey,
        );

        // COLLISION HANDLING: If we already have a session, use a tie-breaker
        if (savedKey) {
          if (targetUsername < user) {
            // THEY WIN: Adopt their session as our new base
            localStorage.setItem(
              `session_${user}_${targetUsername}`,
              rootBase64,
            );
            return { key: rootBase64 };
          } else {
            // WE WIN: Use their key for THIS message only, but keep our own session state
            return { key: rootBase64, isHandshakeCollision: true };
          }
        }

        localStorage.setItem(`session_${user}_${targetUsername}`, rootBase64);
        return { key: rootBase64 };
      } else if (remoteKemCiphertext) {
        // Enforce strict security: reject any handshake missing the ML-DSA-87 signature
        throw new Error(
          "Handshake Security Failure: Missing ML-DSA-87 signature on incoming handshake!",
        );
      } else {
        // INITIATOR
        // 1. Encapsulate a fresh 32-byte shared secret using target's ML-KEM-1024 public key (NIST FIPS 203)
        const { kemCiphertextBase64, rootBase64 } = await encapsulateSharedKey(
          theirPublicIdentity.kemPublicKey,
        );

        // 2. Sign the ML-KEM handshake payload using our ML-DSA-87 private key (NIST FIPS 204)
        const signature = signHandshakePayload(
          user,
          targetUsername,
          kemCiphertextBase64,
          myPrivateKey.dsaSecretKey,
        );

        localStorage.setItem(`session_${user}_${targetUsername}`, rootBase64);
        return {
          key: rootBase64,
          kemCiphertext: kemCiphertextBase64,
          eph: kemCiphertextBase64, // Alias for wire compatibility
          sig: signature,
        };
      }
    },
    [user, myPrivateKey],
  );

  return { getOrCreateSessionKey };
}
