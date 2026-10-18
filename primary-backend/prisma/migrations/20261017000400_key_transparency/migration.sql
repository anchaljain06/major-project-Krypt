-- Key transparency log tables (plan 2.21-2.22). New tables only.

-- CreateTable
CREATE TABLE "KtLeaf" (
    "idx" BIGINT NOT NULL,
    "leaf" BYTEA NOT NULL,
    "leafHash" BYTEA NOT NULL,
    "userHash" BYTEA NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    "ownerSig" BYTEA NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "KtLeaf_pkey" PRIMARY KEY ("idx")
);

-- CreateTable
CREATE TABLE "KtNode" (
    "level" INTEGER NOT NULL,
    "idx" BIGINT NOT NULL,
    "hash" BYTEA NOT NULL,

    CONSTRAINT "KtNode_pkey" PRIMARY KEY ("level","idx")
);

-- CreateTable
CREATE TABLE "KtSth" (
    "treeSize" BIGINT NOT NULL,
    "rootHash" BYTEA NOT NULL,
    "timestamp" BIGINT NOT NULL,
    "signature" BYTEA NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "KtSth_pkey" PRIMARY KEY ("treeSize")
);

-- CreateIndex
CREATE INDEX "KtLeaf_userHash_idx_idx" ON "KtLeaf"("userHash", "idx");
