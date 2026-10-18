-- Bring the migration history in line with the schema that was applied to the
-- deployed database with `prisma db push` (BlockedUser, OfflineMessage and
-- username-keyed FriendRequest never had migrations).
--
-- Written to be idempotent: on a database that `db push` already brought to
-- this state every statement is a no-op, so `prisma migrate deploy` can run it
-- safely. On a fresh database it converts the init schema.

-- FriendRequest: senderId/receiverId (init) -> senderUsername/receiverUsername
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'FriendRequest' AND column_name = 'senderId'
  ) THEN
    ALTER TABLE "FriendRequest" DROP CONSTRAINT IF EXISTS "FriendRequest_receiverId_fkey";
    ALTER TABLE "FriendRequest" DROP CONSTRAINT IF EXISTS "FriendRequest_senderId_fkey";
    DROP INDEX IF EXISTS "FriendRequest_senderId_receiverId_key";

    ALTER TABLE "FriendRequest" ADD COLUMN "senderUsername" TEXT, ADD COLUMN "receiverUsername" TEXT;
    UPDATE "FriendRequest" fr SET "senderUsername" = u."username" FROM "User" u WHERE u."id" = fr."senderId";
    UPDATE "FriendRequest" fr SET "receiverUsername" = u."username" FROM "User" u WHERE u."id" = fr."receiverId";
    UPDATE "FriendRequest" SET "status" = lower("status");
    ALTER TABLE "FriendRequest"
      DROP COLUMN "senderId",
      DROP COLUMN "receiverId",
      ALTER COLUMN "senderUsername" SET NOT NULL,
      ALTER COLUMN "receiverUsername" SET NOT NULL;
  END IF;
END $$;

ALTER TABLE "FriendRequest" ALTER COLUMN "status" SET DEFAULT 'pending';

-- CreateTable
CREATE TABLE IF NOT EXISTS "BlockedUser" (
    "id" TEXT NOT NULL,
    "blockerUsername" TEXT NOT NULL,
    "blockedUsername" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BlockedUser_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE IF NOT EXISTS "OfflineMessage" (
    "id" TEXT NOT NULL,
    "to" TEXT NOT NULL,
    "from" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OfflineMessage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "BlockedUser_blockerUsername_blockedUsername_key" ON "BlockedUser"("blockerUsername", "blockedUsername");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "OfflineMessage_to_idx" ON "OfflineMessage"("to");

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "FriendRequest_senderUsername_receiverUsername_key" ON "FriendRequest"("senderUsername", "receiverUsername");

-- AddForeignKey (only if missing)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'FriendRequest_senderUsername_fkey') THEN
    ALTER TABLE "FriendRequest" ADD CONSTRAINT "FriendRequest_senderUsername_fkey" FOREIGN KEY ("senderUsername") REFERENCES "User"("username") ON DELETE RESTRICT ON UPDATE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'FriendRequest_receiverUsername_fkey') THEN
    ALTER TABLE "FriendRequest" ADD CONSTRAINT "FriendRequest_receiverUsername_fkey" FOREIGN KEY ("receiverUsername") REFERENCES "User"("username") ON DELETE RESTRICT ON UPDATE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'BlockedUser_blockerUsername_fkey') THEN
    ALTER TABLE "BlockedUser" ADD CONSTRAINT "BlockedUser_blockerUsername_fkey" FOREIGN KEY ("blockerUsername") REFERENCES "User"("username") ON DELETE RESTRICT ON UPDATE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'BlockedUser_blockedUsername_fkey') THEN
    ALTER TABLE "BlockedUser" ADD CONSTRAINT "BlockedUser_blockedUsername_fkey" FOREIGN KEY ("blockedUsername") REFERENCES "User"("username") ON DELETE RESTRICT ON UPDATE CASCADE;
  END IF;
END $$;
