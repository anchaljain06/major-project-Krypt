import React, { useState, useCallback } from "react";
import { socket } from "../services/socket";
import { encryptAES } from "../crypto/aes_wasm";
import { db } from "../services/db";
import { useLiveQuery } from "dexie-react-hooks";
import toast from "react-hot-toast";
import { encryptLocal, decryptLocal } from "../crypto/localStore";
import { ratchetKey } from "../crypto/ratchet";
import type { RatchetResult } from "./useRatchet";
import type { UserIdentityKeys } from "../crypto/mlkem";

export interface DecryptedMessage {
  id?: number;
  from: string;
  to: string;
  ciphertext: string;
  decryptedText: string;
  type: "text" | "image" | "audio";
  timestamp: number;
}

export function useChat(
  user: string,
  myPrivateKey: UserIdentityKeys | null,
  getOrCreateSessionKey: (target: string) => Promise<RatchetResult>,
) {
  const [activeChat, setActiveChat] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [previewImage, setPreviewImage] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);
  const rawMessages = useLiveQuery(() => db.messages.toArray()) || [];
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);

  React.useEffect(() => {
    let isMounted = true;
    const decryptAll = async () => {
      if (!myPrivateKey || rawMessages.length === 0) {
        if (isMounted) setMessages([]);
        return;
      }

      const decrypted: DecryptedMessage[] = [];
      for (const msg of rawMessages) {
        if (!msg.payload) continue; // Skip legacy plaintext messages that don't match the new payload schema
        try {
          const jsonStr = await decryptLocal(msg.payload, myPrivateKey);
          const obj = JSON.parse(jsonStr);
          decrypted.push({ ...obj, id: msg.id });
        } catch (e) {
          // If decryption fails, it might be a corrupted or mismatched key msg.
        }
      }

      decrypted.sort((a, b) => a.timestamp - b.timestamp);
      const filtered = decrypted.filter(
        (m) => m.from === user || m.to === user,
      );
      if (isMounted) setMessages(filtered);
    };
    decryptAll();
    return () => {
      isMounted = false;
    };
  }, [rawMessages, myPrivateKey]);

  const sendMessage = useCallback(async () => {
    if (!input.trim() || !activeChat || !myPrivateKey || isSending) return;
    const targetUser = activeChat;
    const plaintext = input;
    setInput("");
    setIsSending(true);

    try {
      // 1. Get current key (optionally initiates handshake)
      const {
        key: currentAesKey,
        eph,
        sig,
      } = await getOrCreateSessionKey(targetUser);

      // 2. Encrypt the text using the WASM engine
      const ciphertext = await encryptAES(plaintext, currentAesKey);

      // 3. THE RATCHET: Hash the key immediately and save it for the NEXT message!
      const nextKey = await ratchetKey(currentAesKey);
      localStorage.setItem(`session_${user}_${targetUser}`, nextKey);

      // 4. Send over socket
      const payload = {
        to: targetUser,
        from: user,
        ciphertext: ciphertext,
        type: "text",
        eph, // Include ephemeral key if it's a new session
        sig, // Include signature
      };

      socket.emit("private_message", payload);

      // 5. Save locally
      const msgObj = {
        from: user,
        to: targetUser,
        decryptedText: plaintext,
        ciphertext,
        type: "text",
        timestamp: Date.now(),
      };

      await db.messages.add({
        payload: await encryptLocal(JSON.stringify(msgObj), myPrivateKey),
      });
    } catch (error: any) {
      toast.error(error.message || "Failed to send message.");
    } finally {
      setIsSending(false);
    }
  }, [input, activeChat, myPrivateKey, isSending, user, getOrCreateSessionKey]);

  const sendImage = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file || !activeChat || !myPrivateKey || isSending) return;
      const MAX_FILE_SIZE = 10 * 1024 * 1024;
      if (file.size > MAX_FILE_SIZE) {
        toast.error("Image is too large (max 10MB)!");
        e.target.value = "";
        return;
      }
      const targetUser = activeChat;
      setIsSending(true);

      const img = new Image();
      const objectUrl = URL.createObjectURL(file);
      img.src = objectUrl;

      img.onload = async () => {
        URL.revokeObjectURL(objectUrl);
        try {
          const canvas = document.createElement("canvas");
          let width = img.width;
          let height = img.height;

          // Scale down if image is too large (max 1200x1200px)
          const MAX_WIDTH = 1200;
          const MAX_HEIGHT = 1200;

          if (width > height) {
            if (width > MAX_WIDTH) {
              height = Math.round((height * MAX_WIDTH) / width);
              width = MAX_WIDTH;
            }
          } else {
            if (height > MAX_HEIGHT) {
              width = Math.round((width * MAX_HEIGHT) / height);
              height = MAX_HEIGHT;
            }
          }

          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext("2d");
          ctx?.drawImage(img, 0, 0, width, height);

          // Optimize image quality before encryption
          const optimizedBase64 = canvas.toDataURL("image/jpeg", 0.7);

          const {
            key: currentAesKey,
            eph,
            sig,
          } = await getOrCreateSessionKey(targetUser);
          const ciphertext = await encryptAES(optimizedBase64, currentAesKey);

          const nextKey = await ratchetKey(currentAesKey);
          localStorage.setItem(`session_${user}_${targetUser}`, nextKey);

          const payload = {
            to: targetUser,
            from: user,
            ciphertext, // directly send the encrypted base64 string
            type: "image",
            eph,
            sig,
          };
          socket.emit("private_message", payload);

          const msgObj = {
            from: user,
            to: targetUser,
            decryptedText: optimizedBase64,
            ciphertext,
            type: "image",
            timestamp: Date.now(),
          };

          await db.messages.add({
            payload: await encryptLocal(JSON.stringify(msgObj), myPrivateKey),
          });
        } catch (err: any) {
          toast.error(err.message || "Failed to send image.");
        } finally {
          setIsSending(false);
          e.target.value = "";
        }
      };

      img.onerror = () => {
        URL.revokeObjectURL(objectUrl);
        toast.error("Invalid image file.");
        setIsSending(false);
        e.target.value = "";
      };
    },
    [activeChat, myPrivateKey, isSending, user, getOrCreateSessionKey],
  );

  const sendAudio = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file || !activeChat || !myPrivateKey || isSending) return;
      const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
      if (file.size > MAX_FILE_SIZE) {
        toast.error("Audio is too large (max 10MB)!");
        e.target.value = "";
        return;
      }

      const targetUser = activeChat;
      setIsSending(true);

      try {
        const reader = new FileReader();
        reader.onloadend = async () => {
          try {
            const base64Audio = reader.result as string;

            const {
              key: currentAesKey,
              eph,
              sig,
            } = await getOrCreateSessionKey(targetUser);
            const ciphertext = await encryptAES(base64Audio, currentAesKey);

            const nextKey = await ratchetKey(currentAesKey);
            localStorage.setItem(`session_${user}_${targetUser}`, nextKey);

            const payload = {
              to: targetUser,
              from: user,
              ciphertext,
              type: "audio",
              eph,
              sig,
            };

            socket.emit("private_message", payload);
            const msgObj = {
              from: user,
              to: targetUser,
              decryptedText: base64Audio,
              ciphertext,
              type: "audio",
              timestamp: Date.now(),
            };

            await db.messages.add({
              payload: await encryptLocal(JSON.stringify(msgObj), myPrivateKey),
            });
          } catch (err: any) {
            toast.error(err.message || "Failed to send audio.");
          } finally {
            setIsSending(false);
            e.target.value = "";
          }
        };

        reader.readAsDataURL(file);
      } catch (err) {
        toast.error("Failed to read audio file.");
        setIsSending(false);
        e.target.value = "";
      }
    },
    [activeChat, myPrivateKey, isSending, user, getOrCreateSessionKey],
  );

  return {
    activeChat,
    setActiveChat,
    input,
    setInput,
    previewImage,
    setPreviewImage,
    messages,
    sendMessage,
    sendImage,
    sendAudio,
    isSending,
  };
}
