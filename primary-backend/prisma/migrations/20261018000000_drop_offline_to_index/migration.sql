-- OfflineMessage_to_createdAt_idx ("to", "createdAt") already serves every
-- lookup by recipient, so the single-column index only costs writes.

-- DropIndex
DROP INDEX IF EXISTS "OfflineMessage_to_idx";
