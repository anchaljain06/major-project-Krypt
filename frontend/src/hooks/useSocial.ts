import { useState, useEffect, useCallback } from "react";
import { apiFetch, apiPostJson } from "../services/api";
import toast from "react-hot-toast";

/** One row of GET /api/users/search. */
export interface SearchResult {
  username: string;
  identityKeyPub?: string | null;
}

export function useSocial(
  user: string,
  activeChat: string | null,
  setActiveChat: (name: string | null) => void,
  signedIn: boolean,
) {
  const [pendingRequests, setPendingRequests] = useState<string[]>([]);
  const [sentRequests, setSentRequests] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
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
        const res = await apiFetch(`/api/users/search?q=${encodeURIComponent(searchQuery)}`);
        if (!res.ok) return setSearchResults([]);
        const data = await res.json();
        setSearchResults(Array.isArray(data) ? data : []);
      } catch {
        setSearchResults([]);
      }
    }, 300);
    return () => clearTimeout(delayDebounceFn);
  }, [searchQuery]);

  // Loaded once the session is live. Keyed on `signedIn` too: a returning
  // login in a new tab starts with `user` already set (from localStorage) but
  // no token, and `user` does not change when the login completes.
  useEffect(() => {
    if (!user || !signedIn) return;
    const endpoints = [
      { url: "request/pending", setter: setPendingRequests, key: "requests" },
      { url: "request/sent", setter: setSentRequests, key: "requests" },
      { url: "friends", setter: setFriendsList, key: "friends" },
      { url: "blocked", setter: setBlockedUsers, key: "blocked" },
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
  }, [user, signedIn]);

  const sendRequest = useCallback(
    async (targetUser: string) => {
      if (targetUser === user) return toast.error("You cannot add yourself!");
      try {
        const res = await apiPostJson("/api/request/send", { receiver: targetUser });
        const data = await res.json();
        if (!res.ok)
          return toast.error(data.error || "Failed to send request.");
        setSentRequests((prev) => [...prev, targetUser]);
        setSearchResults([]);
        setSearchQuery("");
        toast.success(`Request sent to ${targetUser}`);
      } catch {
        toast.error("Failed to send request.");
      }
    },
    [user],
  );

  const acceptRequest = useCallback(
    async (requester: string) => {
      try {
        const res = await apiPostJson("/api/request/accept", { sender: requester });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || "Failed to accept request.");
        }
        setPendingRequests((prev) => prev.filter((r) => r !== requester));
        setFriendsList((prev) => [...prev, requester]);
        toast.success(`You are now friends with ${requester}!`);
      } catch (err) {
        toast.error((err instanceof Error && err.message) || "Failed to accept request.");
      }
    },
    [],
  );

  const rejectRequest = useCallback(
    async (requester: string) => {
      try {
        const res = await apiPostJson("/api/request/reject", { sender: requester });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || "Failed to reject request.");
        }
        setPendingRequests((prev) => prev.filter((r) => r !== requester));
        toast.success(`Request from ${requester} rejected.`);
      } catch (err) {
        toast.error((err instanceof Error && err.message) || "Failed to reject request.");
      }
    },
    [],
  );

  const revokeRequest = useCallback(
    async (targetUser: string) => {
      try {
        const res = await apiPostJson("/api/request/revoke", { receiver: targetUser });
        const data = await res.json();
        if (!res.ok)
          return toast.error(data.error || "Failed to revoke request.");
        setSentRequests((prev) => prev.filter((u) => u !== targetUser));
        toast.success(`Request to ${targetUser} revoked.`);
      } catch {
        toast.error("Failed to revoke request.");
      }
    },
    [],
  );

  const blockUser = useCallback(
    async (targetUser: string) => {
      try {
        const res = await apiPostJson("/api/block", { blocked: targetUser });
        const data = await res.json();
        if (!res.ok) return toast.error(data.error);
        setBlockedUsers((prev) => [...prev, targetUser]);
        setFriendsList((prev) => prev.filter((u) => u !== targetUser));
        setPendingRequests((prev) => prev.filter((u) => u !== targetUser));
        setSentRequests((prev) => prev.filter((u) => u !== targetUser));
        if (activeChat === targetUser) setActiveChat(null);
        toast.success(`${targetUser} blocked.`);
      } catch {
        toast.error("Failed to block user.");
      }
    },
    [activeChat, setActiveChat],
  );

  const unblockUser = useCallback(
    async (targetUser: string) => {
      try {
        const res = await apiPostJson("/api/unblock", { blocked: targetUser });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || "Failed to unblock user.");
        }
        setBlockedUsers((prev) => prev.filter((u) => u !== targetUser));
        toast.success(`${targetUser} unblocked.`);
      } catch (err) {
        toast.error((err instanceof Error && err.message) || "Failed to unblock user.");
      }
    },
    [],
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
