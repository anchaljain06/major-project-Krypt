import { useState, useEffect, useCallback } from "react";
import { socket } from "../services/socket";
import { apiFetch, apiPostJson } from "../services/api";
import toast from "react-hot-toast";

export function useSocial(
  user: string,
  activeChat: string | null,
  setActiveChat: (name: string | null) => void,
) {
  const [pendingRequests, setPendingRequests] = useState<string[]>([]);
  const [sentRequests, setSentRequests] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [friendsList, setFriendsList] = useState<string[]>([]);
  const [blockedUsers, setBlockedUsers] = useState<string[]>([]);
  const [showBlockPanel, setShowBlockPanel] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState<string[]>([]);

  useEffect(() => {
    if (searchQuery.trim().length === 0) {
      setSearchResults([]);
      return;
    }
    const delayDebounceFn = setTimeout(async () => {
      try {
        const res = await apiFetch(
          `/api/users/search?q=${encodeURIComponent(searchQuery)}&current_user=${encodeURIComponent(user)}`,
        );
        if (!res.ok) return setSearchResults([]);
        const data = await res.json();
        setSearchResults(Array.isArray(data) ? data : []);
      } catch (err) {
        setSearchResults([]);
      }
    }, 300);
    return () => clearTimeout(delayDebounceFn);
  }, [searchQuery, user]);

  useEffect(() => {
    if (!user) return;
    const endpoints = [
      {
        url: `request/pending/${user}`,
        setter: setPendingRequests,
        key: "requests",
      },
      { url: `request/sent/${user}`, setter: setSentRequests, key: "requests" },
      { url: `friends/${user}`, setter: setFriendsList, key: "friends" },
      { url: `blocked/${user}`, setter: setBlockedUsers, key: "blocked" },
    ];
    endpoints.forEach(({ url, setter, key }) => {
      apiFetch(`/api/${url}`)
        .then((res) => res.json())
        .then((data) => {
          if (data && data[key]) setter(data[key]);
        })
        .catch(() => {
          // 401 is handled globally by apiFetch (logout); other failures leave lists empty.
        });
    });
  }, [user]);

  const sendRequest = useCallback(
    async (targetUser: string) => {
      if (targetUser === user) return toast.error("You cannot add yourself!");
      try {
        const res = await apiPostJson("/api/request/send", {
          sender: user,
          receiver: targetUser,
        });
        const data = await res.json();
        if (!res.ok)
          return toast.error(data.error || "Failed to send request.");
        socket.emit("send_friend_request", {
          sender: user,
          receiver: targetUser,
        });
        setSentRequests((prev) => [...prev, targetUser]);
        setSearchResults([]);
        setSearchQuery("");
        toast.success(`Request sent to ${targetUser}`);
      } catch (err) {
        toast.error("Failed to send request.");
      }
    },
    [user],
  );

  const acceptRequest = useCallback(
    async (requester: string) => {
      try {
        const res = await apiPostJson("/api/request/accept", {
          sender: requester,
          receiver: user,
        });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || "Failed to accept request.");
        }
        socket.emit("accept_friend_request", {
          sender: requester,
          receiver: user,
        });
        setPendingRequests((prev) => prev.filter((r) => r !== requester));
        setFriendsList((prev) => [...prev, requester]);
        toast.success(`You are now friends with ${requester}!`);
      } catch (err: any) {
        toast.error(err.message || "Failed to accept request.");
      }
    },
    [user],
  );

  const rejectRequest = useCallback(
    async (requester: string) => {
      try {
        const res = await apiPostJson("/api/request/reject", {
          sender: requester,
          receiver: user,
        });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || "Failed to reject request.");
        }
        socket.emit("reject_friend_request", {
          sender: requester,
          receiver: user,
        });
        setPendingRequests((prev) => prev.filter((r) => r !== requester));
        toast.success(`Request from ${requester} rejected.`);
      } catch (err: any) {
        toast.error(err.message || "Failed to reject request.");
      }
    },
    [user],
  );

  const revokeRequest = useCallback(
    async (targetUser: string) => {
      try {
        const res = await apiPostJson("/api/request/revoke", {
          sender: user,
          receiver: targetUser,
        });
        const data = await res.json();
        if (!res.ok)
          return toast.error(data.error || "Failed to revoke request.");

        socket.emit("revoke_friend_request", {
          sender: user,
          receiver: targetUser,
        });
        setSentRequests((prev) => prev.filter((u) => u !== targetUser));
        toast.success(`Request to ${targetUser} revoked.`);
      } catch (err) {
        toast.error("Failed to revoke request.");
      }
    },
    [user],
  );

  const blockUser = useCallback(
    async (targetUser: string) => {
      try {
        const res = await apiPostJson("/api/block", {
          blocker: user,
          blocked: targetUser,
        });
        const data = await res.json();
        if (!res.ok) return toast.error(data.error);
        socket.emit("block_user", { blocker: user, blocked: targetUser });
        setBlockedUsers((prev) => [...prev, targetUser]);
        setFriendsList((prev) => prev.filter((u) => u !== targetUser));
        setPendingRequests((prev) => prev.filter((u) => u !== targetUser));
        setSentRequests((prev) => prev.filter((u) => u !== targetUser));
        if (activeChat === targetUser) setActiveChat(null);
        toast.success(`${targetUser} blocked.`);
      } catch (err) {
        toast.error("Failed to block user.");
      }
    },
    [user, activeChat, setActiveChat],
  );

  const unblockUser = useCallback(
    async (targetUser: string) => {
      try {
        const res = await apiPostJson("/api/unblock", {
          blocker: user,
          blocked: targetUser,
        });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || "Failed to unblock user.");
        }
        setBlockedUsers((prev) => prev.filter((u) => u !== targetUser));
        toast.success(`${targetUser} unblocked.`);
      } catch (err: any) {
        toast.error(err.message || "Failed to unblock user.");
      }
    },
    [user],
  );

  const getRelationship = useCallback(
    (username: string) => {
      if (friendsList.includes(username)) return "friend";
      if (sentRequests.includes(username)) return "sent";
      if (pendingRequests.includes(username)) return "pending";
      return "none";
    },
    [friendsList, sentRequests, pendingRequests],
  );

  const searchUsers = useCallback((query: string) => {
    setSearchQuery(query);
  }, []);

  return {
    pendingRequests,
    setPendingRequests,
    sentRequests,
    setSentRequests,
    searchQuery,
    setSearchQuery,
    searchResults,
    setSearchResults,
    friendsList,
    setFriendsList,
    blockedUsers,
    setBlockedUsers,
    showBlockPanel,
    setShowBlockPanel,
    sendRequest,
    acceptRequest,
    rejectRequest,
    revokeRequest,
    blockUser,
    unblockUser,
    getRelationship,
    searchUsers,
    onlineUsers,
    setOnlineUsers,
  };
}
