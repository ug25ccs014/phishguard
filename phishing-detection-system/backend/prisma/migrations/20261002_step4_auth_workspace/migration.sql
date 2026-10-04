-- Step 4: authentication, sessions, profile preferences and report administration
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "highRiskAlerts" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "weeklySummary" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "passwordChangedAt" TIMESTAMP(3);

CREATE TABLE IF NOT EXISTS "AuthSession" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "revokedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastUsedAt" TIMESTAMP(3),
  "userAgent" TEXT,
  CONSTRAINT "AuthSession_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AuthSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX IF NOT EXISTS "AuthSession_userId_expiresAt_idx" ON "AuthSession"("userId", "expiresAt");
CREATE INDEX IF NOT EXISTS "AuthSession_revokedAt_expiresAt_idx" ON "AuthSession"("revokedAt", "expiresAt");

ALTER TABLE "Scan" ADD COLUMN IF NOT EXISTS "userId" TEXT;
CREATE INDEX IF NOT EXISTS "Scan_verdict_createdAt_idx" ON "Scan"("verdict", "createdAt");

ALTER TABLE "PhishingReport" ADD COLUMN IF NOT EXISTS "reviewedAt" TIMESTAMP(3);
ALTER TABLE "PhishingReport" ADD COLUMN IF NOT EXISTS "reviewedById" TEXT;
ALTER TABLE "PhishingReport" ADD COLUMN IF NOT EXISTS "reviewNote" TEXT;
CREATE INDEX IF NOT EXISTS "PhishingReport_userId_createdAt_idx" ON "PhishingReport"("userId", "createdAt");

ALTER TABLE "ScanResult" ADD COLUMN IF NOT EXISTS "topModelFeaturesJson" JSONB;
ALTER TABLE "ScanResult" ADD COLUMN IF NOT EXISTS "methodology" TEXT;
