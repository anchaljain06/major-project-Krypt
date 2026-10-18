-- Per-recipient byte quota for the offline mailbox. Adds a size column and
-- backfills it for messages already waiting (approximate: jsonb re-serialised).

-- AlterTable
ALTER TABLE "OfflineMessage" ADD COLUMN     "bytes" INTEGER NOT NULL DEFAULT 0;

-- Backfill
UPDATE "OfflineMessage" SET "bytes" = octet_length("payload"::text);
