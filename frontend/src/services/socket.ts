import { io } from "socket.io-client";

// The server authenticates the socket from the token in the handshake and
// registers it for that user itself; the client never claims a username.
export const socket = io(import.meta.env.VITE_API_URL, { autoConnect: false });

export function connectSocket(token: string) {
  socket.auth = { token };
  if (!socket.connected) socket.connect();
}

export function disconnectSocket() {
  socket.disconnect();
  socket.auth = {};
}
