-- Prekey tables for the Krypt-X3K handshake (plan 1.20). New tables only.

-- CreateTable
CREATE TABLE "SignedPrekey" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "keyId" INTEGER NOT NULL,
    "publicKey" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SignedPrekey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OneTimePrekey" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "keyId" INTEGER NOT NULL,
    "publicKey" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OneTimePrekey_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "SignedPrekey_userId_key" ON "SignedPrekey"("userId");

-- CreateIndex
CREATE INDEX "OneTimePrekey_userId_createdAt_idx" ON "OneTimePrekey"("userId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "OneTimePrekey_userId_keyId_key" ON "OneTimePrekey"("userId", "keyId");

-- AddForeignKey
ALTER TABLE "SignedPrekey" ADD CONSTRAINT "SignedPrekey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OneTimePrekey" ADD CONSTRAINT "OneTimePrekey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
