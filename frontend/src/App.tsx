import LoginForm from "./components/LoginForm";
import Sidebar from "./components/Sidebar";
import ChatWindow from "./components/ChatWindow";
import ImagePreview from "./components/ImagePreview";
import VaultBackupModal from "./components/VaultBackupModal";
import { useAuth } from "./hooks/useAuth";
import { useSocial } from "./hooks/useSocial";
import { useChat } from "./hooks/useChat";
import { useSocketListeners } from "./hooks/useSocketListeners";
import { useRatchet } from "./hooks/useRatchet";
import { Toaster } from "react-hot-toast";

export default function App() {
  const {
    user,
    myPrivateKey,
    handleLogin,
    handleLogout,
    handleDownloadVault,
    needsVaultBackup,
    confirmVaultBackup,
    handleExportChats,
    handleImportChats,
    handleWipeCache,
    isLoading,
  } = useAuth();
  const { getOrCreateSessionKey } = useRatchet(user, myPrivateKey);

  const {
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
  } = useChat(user, myPrivateKey, getOrCreateSessionKey);

  const {
    pendingRequests,
    setPendingRequests,
    sentRequests,
    setSentRequests,
    searchQuery,
    searchResults,
    friendsList,
    setFriendsList,
    blockedUsers,
    showBlockPanel,
    setShowBlockPanel,
    sendRequest,
    acceptRequest,
    rejectRequest,
    blockUser,
    unblockUser,
    getRelationship,
    searchUsers,
    onlineUsers,
    setOnlineUsers,
    revokeRequest,
  } = useSocial(user, activeChat, setActiveChat);

  useSocketListeners({
    user,
    myPrivateKey,
    activeChat,
    setActiveChat,
    setPendingRequests,
    setSentRequests,
    setFriendsList,
    getOrCreateSessionKey,
    setOnlineUsers,
  });

  if (!user || !myPrivateKey) {
    return (
      <div className="bg-slate-950 min-h-screen">
        <Toaster
          position="top-right"
          reverseOrder={false}
          toastOptions={{
            style: {
              background: "#1e293b",
              color: "#f8fafc",
              border: "1px solid #334155",
            },
          }}
        />
        <LoginForm onLogin={handleLogin} isLoading={isLoading} />
      </div>
    );
  }

  // After registration the dashboard stays locked until an encrypted vault is saved.
  if (needsVaultBackup) {
    return (
      <div className="bg-slate-950 min-h-screen">
        <Toaster
          position="top-right"
          reverseOrder={false}
          toastOptions={{
            style: {
              background: "#1e293b",
              color: "#f8fafc",
              border: "1px solid #334155",
            },
          }}
        />
        <VaultBackupModal
          user={user}
          onDownload={handleDownloadVault}
          onContinue={confirmVaultBackup}
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center py-8 font-sans">
      <Toaster
        position="top-right"
        reverseOrder={false}
        toastOptions={{
          style: {
            background: "#1e293b",
            color: "#f8fafc",
            border: "1px solid #334155",
          },
        }}
      />
      <div className="w-full max-w-6xl bg-slate-900 shadow-2xl rounded-2xl overflow-hidden flex h-[85vh] border border-slate-800">
        <Sidebar
          user={user}
          activeChat={activeChat}
          setActiveChat={setActiveChat}
          pendingRequests={pendingRequests}
          sentRequests={sentRequests}
          friendsList={friendsList}
          blockedUsers={blockedUsers}
          searchResults={searchResults}
          searchQuery={searchQuery}
          onSearch={searchUsers}
          onSendRequest={sendRequest}
          onAcceptRequest={acceptRequest}
          onRejectRequest={rejectRequest}
          onRevokeRequest={revokeRequest}
          onBlockUser={blockUser}
          onUnblockUser={unblockUser}
          showBlockPanel={showBlockPanel}
          setShowBlockPanel={setShowBlockPanel}
          getRelationship={getRelationship}
          onLogout={handleLogout}
          onDownloadVault={handleDownloadVault}
          onlineUsers={onlineUsers}
          onExportChats={handleExportChats}
          onImportChats={handleImportChats}
          onWipeCache={handleWipeCache}
        />
        <ChatWindow
          user={user}
          activeChat={activeChat}
          messages={messages}
          input={input}
          setInput={setInput}
          onSendMessage={sendMessage}
          onSendImage={sendImage}
          onSendAudio={sendAudio}
          setPreviewImage={setPreviewImage}
          isSending={isSending}
          onlineUsers={onlineUsers}
        />
      </div>
      <ImagePreview
        previewImage={previewImage}
        setPreviewImage={setPreviewImage}
      />
    </div>
  );
}
