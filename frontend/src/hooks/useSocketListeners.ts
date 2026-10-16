import React, { useEffect } from "react";
import { socket } from "../services/socket";
import { decryptAES } from "../crypto/aes_wasm";
import { db } from "../services/db";
import toast from "react-hot-toast";
import { encryptLocal } from "../crypto/localStore";
import { ratchetKey } from "../crypto/ratchet";
import type { RatchetResult } from "./useRatchet";
import type { UserIdentityKeys } from "../crypto/mlkem";

interface SocketListenersProps {
  user: string;
  myPrivateKey: UserIdentityKeys | null;
  activeChat: string | null;
  setActiveChat: (name: string | null) => void;
  setPendingRequests: React.Dispatch<React.SetStateAction<string[]>>;
  setSentRequests: React.Dispatch<React.SetStateAction<string[]>>;
  setFriendsList: React.Dispatch<React.SetStateAction<string[]>>;
  getOrCreateSessionKey: (
    target: string,
    eph?: string,
    sig?: string,
  ) => Promise<RatchetResult>;
  setOnlineUsers: React.Dispatch<React.SetStateAction<string[]>>;
}

export function useSocketListeners({
  user,
  myPrivateKey,
  activeChat,
  setActiveChat,
  setPendingRequests,
  setSentRequests,
  setFriendsList,
  getOrCreateSessionKey,
  setOnlineUsers,
}: SocketListenersProps) {
  useEffect(() => {
    if (!user) return;

    socket.on("online_users", (users: string[]) => {
      setOnlineUsers(users);
    });

    socket.on("user_connected", (connectedUser: string) => {
      setOnlineUsers((prev) =>
        prev.includes(connectedUser) ? prev : [...prev, connectedUser],
      );
    });

    socket.on("user_disconnected", (disconnectedUser: string) => {
      setOnlineUsers((prev) => prev.filter((u) => u !== disconnectedUser));
    });

    socket.on("receive_friend_request", (senderUsername: string) => {
      toast.success(`New friend request from ${senderUsername}!`);
      setPendingRequests((prev) =>
        prev.includes(senderUsername) ? prev : [...prev, senderUsername],
      );
    });

    socket.on("request_accepted", (receiverUsername: string) => {
      toast.success(`${receiverUsername} accepted your friend request!`);
      setSentRequests((prev) => prev.filter((u) => u !== receiverUsername));
      setFriendsList((prev) =>
        prev.includes(receiverUsername) ? prev : [...prev, receiverUsername],
      );
    });

    socket.on("request_rejected", (receiverUsername: string) => {
      toast.error(`${receiverUsername} declined your friend request.`);
      setSentRequests((prev) => prev.filter((u) => u !== receiverUsername));
    });

    socket.on("user_blocked_you", (blockerUsername: string) => {
      setFriendsList((prev) => prev.filter((u) => u !== blockerUsername));
      setPendingRequests((prev) => prev.filter((u) => u !== blockerUsername));
      setSentRequests((prev) => prev.filter((u) => u !== blockerUsername));
      if (activeChat === blockerUsername) setActiveChat(null);
    });

    socket.on("request_revoked", (senderUsername: string) => {
      toast.error(`${senderUsername} revoked their friend request.`);
      setPendingRequests((prev) => prev.filter((u) => u !== senderUsername));
    });

    // FIFO Queue for serial message processing (prevents concurrent ratchet race condition)
    let processingQueue = Promise.resolve();

    socket.on("message_queued", (data: any) => {
      toast(`Message encrypted & queued for ${data?.to || "recipient"} (offline).`, {
        icon: "📬",
        style: { background: "#1e293b", color: "#f8fafc", border: "1px solid #334155" },
      });
    });

    socket.on("message_failed", (data: any) => {
      toast.error(`Delivery failed: ${data.error || "Unknown error"}`);
    });

    socket.on("receive_message", (payload: any) => {
      processingQueue = processingQueue.then(async () => {
        try {
          if (!myPrivateKey) return;

          // 1. Get current key (optionally perform ML-KEM handshake if kemCiphertext/eph and sig are present)
          const incomingKemCiphertext = payload.kemCiphertext || payload.eph;
          const { key: currentAesKey, isHandshakeCollision } =
            await getOrCreateSessionKey(payload.from, incomingKemCiphertext, payload.sig);

          // 2. Decrypt the message
          const plaintext = await decryptAES(payload.ciphertext, currentAesKey);

          // 3. THE RATCHET: Move the lock forward
          // CRITICAL: If this was a handshake collision and we won, DO NOT ratchet.
          if (!isHandshakeCollision) {
            const nextKey = await ratchetKey(currentAesKey);
            localStorage.setItem(`session_${user}_${payload.from}`, nextKey);
          }

          const msgObj = {
            from: payload.from,
            to: user,
            decryptedText: plaintext,
            ciphertext: payload.ciphertext,
            type: payload.type || "text",
            timestamp: Date.now(),
          };

          await db.messages.add({
            payload: await encryptLocal(JSON.stringify(msgObj), myPrivateKey),
          });
        } catch (error: any) {
          toast.error("Decryption failed: " + (error.message || "Unknown error"));
        }
      });
    });

    return () => {
      socket.off("receive_message");
      socket.off("message_queued");
      socket.off("message_failed");
      socket.off("receive_friend_request");
      socket.off("request_accepted");
      socket.off("request_rejected");
      socket.off("user_blocked_you");
      socket.off("request_revoked");
      socket.off("online_users");
      socket.off("user_connected");
      socket.off("user_disconnected");
    };
  }, [
    user,
    myPrivateKey,
    activeChat,
    setActiveChat,
    setPendingRequests,
    setSentRequests,
    setFriendsList,
    getOrCreateSessionKey,
  ]);
}
