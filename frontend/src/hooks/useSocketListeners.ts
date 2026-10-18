import React, { useEffect } from "react";
import { socket } from "../services/socket";
import toast from "react-hot-toast";
import { describeSendFailure, enqueueIncoming, onFileChunk, resumeFileTransfers } from "../services/messaging";

interface SocketListenersProps {
  user: string;
  activeChat: string | null;
  setActiveChat: (name: string | null) => void;
  setPendingRequests: React.Dispatch<React.SetStateAction<string[]>>;
  setSentRequests: React.Dispatch<React.SetStateAction<string[]>>;
  setFriendsList: React.Dispatch<React.SetStateAction<string[]>>;
  setOnlineUsers: React.Dispatch<React.SetStateAction<string[]>>;
}

export function useSocketListeners({
  user,
  activeChat,
  setActiveChat,
  setPendingRequests,
  setSentRequests,
  setFriendsList,
  setOnlineUsers,
}: SocketListenersProps) {
  // Messages: one FIFO queue (services/messaging.ts) that waits for the
  // Protocol to be ready, so nothing flushed from the mailbox is lost.
  useEffect(() => {
    if (!user) return;
    const onMessage = (payload: unknown) => enqueueIncoming(payload);
    const onQueued = (data: { to?: string } | undefined) => {
      toast(`Message encrypted & queued for ${data?.to || "recipient"} (offline).`, { icon: "📬" });
    };
    const onFailed = (data: { to?: unknown; reason?: unknown; error?: unknown }) => {
      toast.error(describeSendFailure(data ?? {}));
    };
    socket.on("receive_message", onMessage);
    socket.on("message_queued", onQueued);
    socket.on("message_failed", onFailed);
    return () => {
      socket.off("receive_message", onMessage);
      socket.off("message_queued", onQueued);
      socket.off("message_failed", onFailed);
    };
  }, [user]);

  // Large files (spec 15): chunks arrive as binary frames. After our own
  // reconnect, or when a sender comes back online, ask senders to resume.
  useEffect(() => {
    if (!user) return;
    const onReconnect = () => resumeFileTransfers();
    const onPeerOnline = (peer: string) => resumeFileTransfers(peer);
    socket.on("file:chunk", onFileChunk);
    socket.on("connect", onReconnect);
    socket.on("user_connected", onPeerOnline);
    return () => {
      socket.off("file:chunk", onFileChunk);
      socket.off("connect", onReconnect);
      socket.off("user_connected", onPeerOnline);
    };
  }, [user]);

  useEffect(() => {
    if (!user) return;

    const onOnline = (users: string[]) => setOnlineUsers(users);
    const onConnected = (connectedUser: string) =>
      setOnlineUsers((prev) => (prev.includes(connectedUser) ? prev : [...prev, connectedUser]));
    const onDisconnected = (disconnectedUser: string) =>
      setOnlineUsers((prev) => prev.filter((u) => u !== disconnectedUser));
    const onFriendRequest = (senderUsername: string) => {
      toast.success(`New friend request from ${senderUsername}!`);
      setPendingRequests((prev) => (prev.includes(senderUsername) ? prev : [...prev, senderUsername]));
    };
    const onAccepted = (receiverUsername: string) => {
      toast.success(`${receiverUsername} accepted your friend request!`);
      setSentRequests((prev) => prev.filter((u) => u !== receiverUsername));
      setFriendsList((prev) => (prev.includes(receiverUsername) ? prev : [...prev, receiverUsername]));
    };
    const onRejected = (receiverUsername: string) => {
      toast.error(`${receiverUsername} declined your friend request.`);
      setSentRequests((prev) => prev.filter((u) => u !== receiverUsername));
    };
    const onBlocked = (blockerUsername: string) => {
      setFriendsList((prev) => prev.filter((u) => u !== blockerUsername));
      setPendingRequests((prev) => prev.filter((u) => u !== blockerUsername));
      setSentRequests((prev) => prev.filter((u) => u !== blockerUsername));
      if (activeChat === blockerUsername) setActiveChat(null);
    };
    const onRevoked = (senderUsername: string) => {
      toast.error(`${senderUsername} revoked their friend request.`);
      setPendingRequests((prev) => prev.filter((u) => u !== senderUsername));
    };

    socket.on("online_users", onOnline);
    socket.on("user_connected", onConnected);
    socket.on("user_disconnected", onDisconnected);
    socket.on("receive_friend_request", onFriendRequest);
    socket.on("request_accepted", onAccepted);
    socket.on("request_rejected", onRejected);
    socket.on("user_blocked_you", onBlocked);
    socket.on("request_revoked", onRevoked);
    return () => {
      socket.off("online_users", onOnline);
      socket.off("user_connected", onConnected);
      socket.off("user_disconnected", onDisconnected);
      socket.off("receive_friend_request", onFriendRequest);
      socket.off("request_accepted", onAccepted);
      socket.off("request_rejected", onRejected);
      socket.off("user_blocked_you", onBlocked);
      socket.off("request_revoked", onRevoked);
    };
  }, [user, activeChat, setActiveChat, setPendingRequests, setSentRequests, setFriendsList, setOnlineUsers]);
}
