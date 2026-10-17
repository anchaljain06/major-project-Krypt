import React, { useState, useCallback } from "react";
import { db } from "../services/db";
import { useLiveQuery } from "dexie-react-hooks";
import toast from "react-hot-toast";
import { decryptLocal } from "../crypto/localStore";
import type { UserIdentityKeys } from "../crypto/mlkem";
import { MAX_ATTACHMENT_BYTES, formatBytes } from "../crypto/media";
import type { Protocol } from "../services/protocol";
import { reportSendError, sendChatMessage, type StoredMessage } from "../services/messaging";

export type DecryptedMessage = StoredMessage;

/** Images above this are refused before decoding (they are re-encoded to JPEG ≤ 1200 px anyway). */
const MAX_IMAGE_INPUT_BYTES = 50 * 1024 * 1024;
const MAX_IMAGE_SIDE = 1200;

/** Decodes, downsizes and re-encodes an image as JPEG (quality 0.7). */
async function prepareImage(file: File): Promise<Uint8Array> {
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    img.src = url;
    await img.decode().catch(() => {
      throw new Error("Invalid image file.");
    });
    let { width, height } = img;
    const scale = Math.min(1, MAX_IMAGE_SIDE / Math.max(width, height));
    width = Math.round(width * scale);
    height = Math.round(height * scale);
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    canvas.getContext("2d")?.drawImage(img, 0, 0, width, height);
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.7));
    if (!blob) throw new Error("Could not encode the image.");
    return new Uint8Array(await blob.arrayBuffer());
  } finally {
    URL.revokeObjectURL(url);
  }
}

export function useChat(user: string, myPrivateKey: UserIdentityKeys | null, protocol: Protocol | null) {
  const [activeChat, setActiveChat] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [previewImage, setPreviewImage] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);
  const rawMessages = useLiveQuery(() => db.messages.toArray());
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);

  React.useEffect(() => {
    let isMounted = true;
    const decryptAll = async () => {
      const rows = rawMessages ?? [];
      if (!myPrivateKey || rows.length === 0) {
        if (isMounted) setMessages([]);
        return;
      }
      const decrypted: DecryptedMessage[] = [];
      for (const msg of rows) {
        if (!msg.payload) continue;
        try {
          const obj = JSON.parse(await decryptLocal(msg.payload, myPrivateKey));
          decrypted.push({ ...obj, id: msg.id });
        } catch {
          // Unreadable entry (other account's key or corrupted): skip it.
        }
      }
      decrypted.sort((a, b) => a.timestamp - b.timestamp);
      if (isMounted) setMessages(decrypted.filter((m) => m.from === user || m.to === user));
    };
    decryptAll();
    return () => {
      isMounted = false;
    };
  }, [rawMessages, myPrivateKey, user]);

  const sendMessage = useCallback(async () => {
    if (!input.trim() || !activeChat || isSending) return;
    if (!protocol) {
      toast.error("Secure messaging is still starting. Try again in a moment.");
      return;
    }
    const targetUser = activeChat;
    const text = input;
    setInput("");
    setIsSending(true);
    try {
      await sendChatMessage(protocol, targetUser, { type: "text", text });
    } catch (err) {
      setInput((cur) => (cur === "" ? text : cur));
      reportSendError(err, targetUser);
    } finally {
      setIsSending(false);
    }
  }, [input, activeChat, isSending, protocol]);

  const sendImage = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      e.target.value = "";
      if (!file || !activeChat || isSending) return;
      if (!protocol) {
        toast.error("Secure messaging is still starting. Try again in a moment.");
        return;
      }
      if (file.size > MAX_IMAGE_INPUT_BYTES) {
        toast.error(`Image is too large (max ${formatBytes(MAX_IMAGE_INPUT_BYTES)}).`);
        return;
      }
      const targetUser = activeChat;
      setIsSending(true);
      try {
        const jpeg = await prepareImage(file);
        await sendChatMessage(protocol, targetUser, { type: "image", data: jpeg, mime: "image/jpeg" });
      } catch (err) {
        reportSendError(err, targetUser);
      } finally {
        setIsSending(false);
      }
    },
    [activeChat, isSending, protocol],
  );

  const sendAudio = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      e.target.value = "";
      if (!file || !activeChat || isSending) return;
      if (!protocol) {
        toast.error("Secure messaging is still starting. Try again in a moment.");
        return;
      }
      // Checked before reading the file: one relay frame holds at most this much.
      if (file.size > MAX_ATTACHMENT_BYTES) {
        toast.error(`Audio is too large: ${formatBytes(file.size)} (limit ${formatBytes(MAX_ATTACHMENT_BYTES)}).`);
        return;
      }
      const mime = file.type && file.type.startsWith("audio/") ? file.type : "audio/mpeg";
      const targetUser = activeChat;
      setIsSending(true);
      try {
        const data = new Uint8Array(await file.arrayBuffer());
        await sendChatMessage(protocol, targetUser, { type: "audio", data, mime });
      } catch (err) {
        reportSendError(err, targetUser);
      } finally {
        setIsSending(false);
      }
    },
    [activeChat, isSending, protocol],
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
