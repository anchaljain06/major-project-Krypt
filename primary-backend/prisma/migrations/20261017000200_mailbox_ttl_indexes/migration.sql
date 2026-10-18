-- Indexes for mailbox flush ordering, quota counts and TTL purges.

-- CreateIndex
CREATE INDEX "OfflineMessage_to_createdAt_idx" ON "OfflineMessage"("to", "createdAt");

-- CreateIndex
CREATE INDEX "OfflineMessage_createdAt_idx" ON "OfflineMessage"("createdAt");
