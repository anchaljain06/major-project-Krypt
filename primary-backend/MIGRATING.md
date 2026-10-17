# Applying the database migrations to Neon

The deployed Neon database was built with `prisma db push`, so its migration
history does not match `prisma/migrations/`. Follow these steps once to bring it
under `prisma migrate deploy`. After that, every future change is just
`npx prisma migrate deploy`.

**Never run `prisma migrate dev`, `prisma migrate reset` or `prisma db push`
against Neon.** `migrate dev` and `reset` can drop and recreate the database.
`db push` skips the history again.

## The migrations

| # | Migration | What it changes | Touches existing rows? |
|---|-----------|-----------------|------------------------|
| 1 | `20260420135802_init` | Original `User` and `FriendRequest` tables. Neon already has these. | Not run on Neon (marked as applied in step 3) |
| 2 | `20261017000000_sync_db_push_schema` | Records what `db push` created: `BlockedUser`, `OfflineMessage`, username-keyed `FriendRequest`. Every statement is guarded (`IF NOT EXISTS`, column checks), so on Neon it does nothing. | No |
| 3 | `20261017000100_social_fks_to_user_id` | `FriendRequest` and `BlockedUser` switch from usernames to `User.id`: adds `senderId`/`receiverId` and `blockerId`/`blockedId`, backfills them from usernames, then drops the username columns. One transaction. | **Yes: rewrites every FriendRequest and BlockedUser row** |
| 4 | `20261017000200_mailbox_ttl_indexes` | Two new indexes on `OfflineMessage`. | No |
| 5 | `20261017000300_prekeys` | New tables `SignedPrekey` and `OneTimePrekey`. | No |
| 6 | `20261017000400_key_transparency` | New tables `KtLeaf`, `KtNode`, `KtSth` for the key transparency log. | No |
| 7 | `20261017000500_mailbox_bytes` | Adds `OfflineMessage.bytes` (payload size, for the 50 MB per-recipient quota) and backfills it. | **Yes: one UPDATE over waiting offline messages** (sets only the new column) |

### How migration 3 keeps your data

1. Adds the new id columns as nullable.
2. Fills them with `UPDATE ... FROM "User" WHERE username = ...`.
3. Checks that no row is left with a NULL id. If one is, it raises an error and
   the whole transaction rolls back, so nothing changes.
4. Only then drops the old username columns, indexes and foreign keys, and adds
   the new ones.

The old username foreign keys already guarantee that every username matches a
user, so step 3 should never fire. The API returns exactly the same JSON as
before: usernames, not ids.

This was tested on a local Postgres. A database in the `db push` state, with
friends, pending and rejected requests and blocks, kept every row through the
migration. The rollback script below restored them, and re-applying the
migration then succeeded.

## Steps

You need `DIRECT_URL` (the non-pooled Neon connection string). Run all commands
from `primary-backend/`.

### 1. Try it on a Neon branch first

In the Neon console, create a branch from `main`, for example
`migrate-test-2026-10`. A branch is an instant copy of your data. Point a shell
at it:

```sh
export DATABASE_URL="<branch pooled URL>"
export DIRECT_URL="<branch direct URL>"
```

Do steps 2 to 5 on the branch. When they all pass, delete the branch and repeat
steps 2 to 5 with the `main` URLs.

### 2. Look at the current state

```sh
npx prisma migrate status
```

You will see one of two things:

- **"The database schema is not empty"** or no migrations recorded: the
  `_prisma_migrations` table does not exist yet. Do step 3.
- **`20260420135802_init` listed as applied**: skip step 3.

### 3. Mark the init migration as applied (baseline)

```sh
npx prisma migrate resolve --applied 20260420135802_init
```

This writes one row to `_prisma_migrations`. It runs no SQL against your tables.

Run `npx prisma migrate status` again. It should list migrations 2 to 7 as
pending, and nothing else.

### 4. Apply

```sh
npx prisma migrate deploy
```

Expected output: migrations 2 to 7 listed as applied.

### 5. Verify

```sh
npx prisma migrate status            # "Database schema is up to date!"
npx prisma migrate diff --from-url "$DIRECT_URL" \
  --to-schema-datamodel prisma/schema.prisma --script
                                     # "-- This is an empty migration."
```

Then spot-check the data in the Neon SQL editor:

```sql
SELECT s.username AS sender, r.username AS receiver, fr.status
FROM "FriendRequest" fr
JOIN "User" s ON s.id = fr."senderId"
JOIN "User" r ON r.id = fr."receiverId";

SELECT count(*) FROM "BlockedUser";
```

Compare against the same counts taken before step 4.

## Deploying the code

The new backend requires a bearer token on every REST route and socket, so
deploy the backend and the matching frontend together. Before starting the new
server, set these on the host:

- `AUTH_TOKEN_SECRET`: a long random value, e.g.
  `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`.
  If it is unset, tokens stop working on every restart.
- `AUTH_TOKEN_TTL_SECONDS`: optional, default 43200 (12 h).
- `KT_LOG_SK`: the key transparency log's ML-DSA-87 signing key. Generate it
  once with `npm run kt:keygen` and keep it forever: it is the log's
  identity. The command also prints the public key. Pin that key in the
  frontend build and set it as the witness's `KRYPT_LOG_PUBKEY`. If
  `KT_LOG_SK` is unset, the server uses a random key on every start. No
  witness or client will accept a log signed that way. `KT_LOG_SK` accepts a
  32-byte seed (what keygen prints) or a 4896-byte secret key, both standard
  base64.
- `KT_STH_INTERVAL_SECONDS`: optional, default 300. This is the minimum time
  between signed tree heads. Leave it at the default in production. Each head
  is about 4.7 KB in `KtSth`.
- Do **not** set `EVIL_MODE` in production.

### Key transparency endpoints

These are public and need no token, because the witness calls them:

| Endpoint | Returns |
|---|---|
| `GET /kt/sth` | The latest signed tree head. |
| `GET /kt/consistency?from=&to=` | A consistency proof between two tree sizes. |
| `GET /kt/proof?user=&size=` | A user's latest leaf, with an inclusion proof. |
| `GET /kt/leaves?from=&to=` | Leaves in a range, at most 1000 per page. |
| `GET /kt/pubkey` | The log's public key. Use it to copy the key into config, never as a trust anchor. |

Two endpoints need a token:

- `POST /api/kt/register` takes `{ leaf, ownerSig, signerPk? }`.
- `GET /api/kt/status` returns `{ hasLeaf, keyVersion }`.

The server publishes a tree head lazily: on an append or a `/kt/sth` read,
when the log has grown and the last head is at least 5 minutes old. A new
leaf can therefore take up to 5 minutes to show in `/kt/*`.

### Consuming `shared/`

Render builds from `primary-backend/` only. For that reason the KT package
in `../shared/src` is copied into `src/vendor/krypt-shared/`, and the copy is
committed. After you change `shared/`, run `npm run vendor:shared`.
`test/vendor.test.ts` fails if the copy is stale.

## Rollback

**Easiest:** Neon's point-in-time restore. Before step 4, note the time or
create a branch named `pre-migration`. To roll back, restore `main` to that
point, or promote the branch. This also covers migrations 4 to 7.

**Manual, for migration 3 only.** This was tested locally: it restored every
row, and the forward migration re-applied cleanly afterwards. Run it in the
Neon SQL editor, then deploy a backend from before commit `cf7b778`:

```sql
BEGIN;

ALTER TABLE "FriendRequest" ADD COLUMN "senderUsername" TEXT, ADD COLUMN "receiverUsername" TEXT;
ALTER TABLE "BlockedUser" ADD COLUMN "blockerUsername" TEXT, ADD COLUMN "blockedUsername" TEXT;

UPDATE "FriendRequest" fr SET "senderUsername" = u."username" FROM "User" u WHERE u."id" = fr."senderId";
UPDATE "FriendRequest" fr SET "receiverUsername" = u."username" FROM "User" u WHERE u."id" = fr."receiverId";
UPDATE "BlockedUser" b SET "blockerUsername" = u."username" FROM "User" u WHERE u."id" = b."blockerId";
UPDATE "BlockedUser" b SET "blockedUsername" = u."username" FROM "User" u WHERE u."id" = b."blockedId";

ALTER TABLE "FriendRequest" DROP CONSTRAINT "FriendRequest_senderId_fkey", DROP CONSTRAINT "FriendRequest_receiverId_fkey";
ALTER TABLE "BlockedUser" DROP CONSTRAINT "BlockedUser_blockerId_fkey", DROP CONSTRAINT "BlockedUser_blockedId_fkey";
DROP INDEX "FriendRequest_senderId_receiverId_key";
DROP INDEX "FriendRequest_receiverId_idx";
DROP INDEX "BlockedUser_blockerId_blockedId_key";
DROP INDEX "BlockedUser_blockedId_idx";

ALTER TABLE "FriendRequest" DROP COLUMN "senderId", DROP COLUMN "receiverId",
  ALTER COLUMN "senderUsername" SET NOT NULL, ALTER COLUMN "receiverUsername" SET NOT NULL;
ALTER TABLE "BlockedUser" DROP COLUMN "blockerId", DROP COLUMN "blockedId",
  ALTER COLUMN "blockerUsername" SET NOT NULL, ALTER COLUMN "blockedUsername" SET NOT NULL;

CREATE UNIQUE INDEX "FriendRequest_senderUsername_receiverUsername_key" ON "FriendRequest"("senderUsername", "receiverUsername");
CREATE UNIQUE INDEX "BlockedUser_blockerUsername_blockedUsername_key" ON "BlockedUser"("blockerUsername", "blockedUsername");
ALTER TABLE "FriendRequest" ADD CONSTRAINT "FriendRequest_senderUsername_fkey" FOREIGN KEY ("senderUsername") REFERENCES "User"("username") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "FriendRequest" ADD CONSTRAINT "FriendRequest_receiverUsername_fkey" FOREIGN KEY ("receiverUsername") REFERENCES "User"("username") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "BlockedUser" ADD CONSTRAINT "BlockedUser_blockerUsername_fkey" FOREIGN KEY ("blockerUsername") REFERENCES "User"("username") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "BlockedUser" ADD CONSTRAINT "BlockedUser_blockedUsername_fkey" FOREIGN KEY ("blockedUsername") REFERENCES "User"("username") ON DELETE RESTRICT ON UPDATE CASCADE;

DELETE FROM "_prisma_migrations" WHERE migration_name = '20261017000100_social_fks_to_user_id';

COMMIT;
```

To roll back migration 7, drop the column `OfflineMessage.bytes`. To roll
back migration 6, drop the tables `KtSth`, `KtNode` and `KtLeaf`. Dropping
them deletes the log. Clients and the witness that saw a tree head will then
report the reset log as a fork. Only do this before anyone relies on it.
To roll back migration 5, drop `OneTimePrekey` and `SignedPrekey`; they hold
only public keys. To roll back migration 4, drop the two
`OfflineMessage_*createdAt*` indexes. In both cases, delete the matching row
from `_prisma_migrations`.
