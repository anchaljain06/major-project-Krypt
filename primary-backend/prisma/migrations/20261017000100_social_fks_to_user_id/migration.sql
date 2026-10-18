-- FriendRequest and BlockedUser: reference User.id instead of User.username.
-- Existing rows are backfilled from usernames in SQL; nothing is dropped until
-- every row has its id. Runs in one transaction: any failure leaves the
-- database unchanged.

BEGIN;

-- 1. Add the id columns (nullable while backfilling)
ALTER TABLE "FriendRequest" ADD COLUMN "senderId" TEXT, ADD COLUMN "receiverId" TEXT;
ALTER TABLE "BlockedUser" ADD COLUMN "blockerId" TEXT, ADD COLUMN "blockedId" TEXT;

-- 2. Backfill from usernames
UPDATE "FriendRequest" fr SET "senderId" = u."id" FROM "User" u WHERE u."username" = fr."senderUsername";
UPDATE "FriendRequest" fr SET "receiverId" = u."id" FROM "User" u WHERE u."username" = fr."receiverUsername";
UPDATE "BlockedUser" b SET "blockerId" = u."id" FROM "User" u WHERE u."username" = b."blockerUsername";
UPDATE "BlockedUser" b SET "blockedId" = u."id" FROM "User" u WHERE u."username" = b."blockedUsername";

-- 3. The old username FKs guarantee a match; stop if that ever was not true
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM "FriendRequest" WHERE "senderId" IS NULL OR "receiverId" IS NULL) THEN
    RAISE EXCEPTION 'FriendRequest backfill incomplete: a username has no matching User';
  END IF;
  IF EXISTS (SELECT 1 FROM "BlockedUser" WHERE "blockerId" IS NULL OR "blockedId" IS NULL) THEN
    RAISE EXCEPTION 'BlockedUser backfill incomplete: a username has no matching User';
  END IF;
END $$;

-- 4. Drop the username keys
ALTER TABLE "FriendRequest" DROP CONSTRAINT "FriendRequest_senderUsername_fkey";
ALTER TABLE "FriendRequest" DROP CONSTRAINT "FriendRequest_receiverUsername_fkey";
ALTER TABLE "BlockedUser" DROP CONSTRAINT "BlockedUser_blockerUsername_fkey";
ALTER TABLE "BlockedUser" DROP CONSTRAINT "BlockedUser_blockedUsername_fkey";
DROP INDEX "FriendRequest_senderUsername_receiverUsername_key";
DROP INDEX "BlockedUser_blockerUsername_blockedUsername_key";

ALTER TABLE "FriendRequest"
  DROP COLUMN "senderUsername",
  DROP COLUMN "receiverUsername",
  ALTER COLUMN "senderId" SET NOT NULL,
  ALTER COLUMN "receiverId" SET NOT NULL;

ALTER TABLE "BlockedUser"
  DROP COLUMN "blockerUsername",
  DROP COLUMN "blockedUsername",
  ALTER COLUMN "blockerId" SET NOT NULL,
  ALTER COLUMN "blockedId" SET NOT NULL;

-- 5. New indexes and FKs
CREATE INDEX "BlockedUser_blockedId_idx" ON "BlockedUser"("blockedId");
CREATE UNIQUE INDEX "BlockedUser_blockerId_blockedId_key" ON "BlockedUser"("blockerId", "blockedId");
CREATE INDEX "FriendRequest_receiverId_idx" ON "FriendRequest"("receiverId");
CREATE UNIQUE INDEX "FriendRequest_senderId_receiverId_key" ON "FriendRequest"("senderId", "receiverId");

ALTER TABLE "FriendRequest" ADD CONSTRAINT "FriendRequest_senderId_fkey" FOREIGN KEY ("senderId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "FriendRequest" ADD CONSTRAINT "FriendRequest_receiverId_fkey" FOREIGN KEY ("receiverId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "BlockedUser" ADD CONSTRAINT "BlockedUser_blockerId_fkey" FOREIGN KEY ("blockerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "BlockedUser" ADD CONSTRAINT "BlockedUser_blockedId_fkey" FOREIGN KEY ("blockedId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

COMMIT;
