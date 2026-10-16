import React, { useRef, useEffect } from "react";

interface SavedMessage {
  id?: number;
  from: string;
  to: string;
  ciphertext: string;
  decryptedText: string;
  type: "text" | "image" | "audio";
  timestamp: number;
}

interface ChatWindowProps {
  user: string;
  activeChat: string | null;
  messages: SavedMessage[];
  input: string;
  setInput: (val: string) => void;
  onSendMessage: () => void;
  onSendImage: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onSendAudio: (e: React.ChangeEvent<HTMLInputElement>) => void;
  setPreviewImage: (url: string | null) => void;
  isSending: boolean;
  onlineUsers: string[];
}

const ChatWindow: React.FC<ChatWindowProps> = ({
  user,
  activeChat,
  messages,
  input,
  setInput,
  onSendMessage,
  onSendImage,
  onSendAudio,
  setPreviewImage,
  isSending,
  onlineUsers,
}) => {
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const isTargetOnline = activeChat ? onlineUsers.includes(activeChat) : false;
  const isInputDisabled = isSending;

  return (
    <div
      className={`flex-1 flex flex-col bg-slate-950 ${isSending ? "cursor-wait" : ""}`}
    >
      {activeChat ? (
        <>
          <div className="h-20 px-6 border-b border-slate-800 bg-slate-900 flex items-center justify-between shadow-sm z-0">
            <div className="flex items-center gap-4">
              <div className="h-10 w-10 bg-indigo-900/30 text-indigo-400 border border-indigo-800/50 rounded-full flex items-center justify-center font-bold text-lg shadow-inner">
                {activeChat.charAt(0).toUpperCase()}
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100">
                  {activeChat}
                </h3>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span
                    className={`inline-block w-2 h-2 rounded-full ${
                      isTargetOnline ? "bg-emerald-400 shadow-sm shadow-emerald-400/50" : "bg-amber-400"
                    }`}
                  />
                  <p className="text-xs text-slate-400 font-medium">
                    {isTargetOnline ? "Online" : "Offline"} • ML-KEM-1024 / AES-GCM {isTargetOnline ? "" : "(Mailbox Active)"}
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="flex-1 p-6 overflow-y-auto">
            {messages.filter(
              (m) => m.to === activeChat || m.from === activeChat,
            ).length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3">
                <div className="p-4 bg-slate-800/50 rounded-full">
                  <svg
                    className="w-8 h-8 text-slate-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                    ></path>
                  </svg>
                </div>
                <p>Send a message to initiate the Hybrid Key Exchange.</p>
              </div>
            ) : (
              messages
                .filter((m) => m.to === activeChat || m.from === activeChat)
                .map((msg, i) => {
                  const isMe = msg.from === user;
                  return (
                    <div
                      key={i}
                      className={`mb-6 flex flex-col ${isMe ? "items-end" : "items-start"}`}
                    >
                      <div
                        className={`px-3 py-2 rounded-2xl max-w-[75%] shadow-sm min-w-0 ${
                          isMe
                            ? "bg-indigo-600 text-white rounded-br-none"
                            : "bg-slate-800 border border-slate-700 text-slate-200 rounded-bl-none"
                        }`}
                      >
                        {msg.type === "image" ? (
                          <img
                            src={msg.decryptedText}
                            alt="Secure shared"
                            onClick={() => setPreviewImage(msg.decryptedText)}
                            className="max-w-full max-h-62.5 rounded-xl object-contain block mx-auto cursor-zoom-in hover:opacity-90 transition-opacity"
                            loading="lazy"
                          />
                        ) : msg.type === "audio" ? (
                          <audio
                            controls
                            src={msg.decryptedText}
                            className="max-w-full h-10 outline-none"
                          />
                        ) : (
                          <p className="text-sm px-1 py-1 break-all whitespace-pre-wrap min-w-0">
                            {msg.decryptedText}
                          </p>
                        )}
                      </div>
                      <div
                        className={`mt-1 flex items-center gap-2 text-[10px] text-slate-500 max-w-[75%] ${isMe ? "flex-row-reverse" : "flex-row"}`}
                      >
                        <span>
                          {new Date(msg.timestamp).toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </span>
                      </div>
                    </div>
                  );
                })
            )}
            <div ref={messagesEndRef} />
          </div>

          <div className="p-4 bg-slate-900 border-t border-slate-800">
            <div className="flex gap-3 items-center max-w-4xl mx-auto">
              <input
                type="file"
                accept="image/*"
                id="image-upload"
                className="hidden"
                onChange={onSendImage}
                disabled={isInputDisabled}
              />
              <label
                htmlFor={isInputDisabled ? undefined : "image-upload"}
                className={`p-3 bg-slate-800 text-slate-400 rounded-xl transition-colors border border-slate-700 shadow-sm ${isInputDisabled ? "opacity-50 cursor-not-allowed" : "hover:bg-slate-700 cursor-pointer"}`}
                title={
                  isInputDisabled
                    ? "Target offline or calculating handshake"
                    : "Send Encrypted Image"
                }
              >
                <svg
                  className="w-6 h-6"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"
                  ></path>
                </svg>
              </label>

              <input
                type="file"
                accept="audio/*"
                id="audio-upload"
                className="hidden"
                onChange={onSendAudio}
                disabled={isInputDisabled}
              />
              <label
                htmlFor={isInputDisabled ? undefined : "audio-upload"}
                className={`p-3 bg-slate-800 text-slate-400 rounded-xl transition-colors border border-slate-700 shadow-sm ${isInputDisabled ? "opacity-50 cursor-not-allowed" : "hover:bg-slate-700 cursor-pointer"}`}
                title={
                  isInputDisabled
                    ? "Target offline or calculating handshake"
                    : "Send Encrypted Audio"
                }
              >
                <svg
                  className="w-6 h-6"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z"
                  ></path>
                </svg>
              </label>

              <input
                placeholder={
                  isSending
                    ? "Calculating cryptographic handshake..."
                    : isTargetOnline
                      ? `Secure message to ${activeChat}...`
                      : `Secure message to ${activeChat} (queued offline)...`
                }
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) =>
                  e.key === "Enter" && !isInputDisabled && onSendMessage()
                }
                disabled={isInputDisabled}
                className="flex-1 px-4 py-3 bg-slate-950 border border-slate-800 focus:bg-slate-900 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/50 rounded-xl transition-all outline-none text-slate-100 placeholder-slate-500 disabled:opacity-50 shadow-inner"
              />
              <button
                type="button"
                onClick={(e) => {
                  e.preventDefault();
                  onSendMessage();
                }}
                disabled={isInputDisabled || !input.trim()}
                className="p-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl shadow-md hover:shadow-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg
                  className="w-6 h-6 transform rotate-45 -mt-1 ml-1"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                  ></path>
                </svg>
              </button>
            </div>
          </div>
        </>
      ) : (
        <div className="flex-1 flex flex-col items-center justify-center bg-slate-950 text-slate-500">
          <svg
            className="w-20 h-20 mb-4 text-slate-800"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="1"
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
            ></path>
          </svg>
          <h2 className="text-xl font-medium text-slate-400 mb-2">
            No connection selected
          </h2>
          <p className="text-sm">
            Search for a user in the sidebar to open a secure channel.
          </p>
        </div>
      )}
    </div>
  );
};

export default ChatWindow;