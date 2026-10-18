import type { Server } from "socket.io";

// Presence registry shared by the socket layer and REST handlers.
// Map<username, socketId>; a user is only added after their mailbox is flushed.

export const onlineUsers = new Map<string, string>();

let ioRef: Server | null = null;

export function setIo(io: Server) {
  ioRef = io;
}

/** Emit to a user's live socket. Returns false if they are offline. */
export function emitToUser(username: string, event: string, ...args: unknown[]): boolean {
  const socketId = onlineUsers.get(username);
  if (!socketId || !ioRef) return false;
  ioRef.to(socketId).emit(event, ...args);
  return true;
}
