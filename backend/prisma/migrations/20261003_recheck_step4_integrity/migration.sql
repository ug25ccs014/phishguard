-- Recheck Step 4: database integrity hardening.
-- Kept as a new migration so already-applied historical migrations remain immutable.

-- Backfill model registry entries from historical scans before enforcing application-level registry use.
INSERT INTO "ModelVersion" ("id", "name", "version", "createdAt")
SELECT md5('phishguard-model:' || s."modelVersion"), left(s."modelVersion", 200), s."modelVersion", MIN(s."createdAt")
FROM "Scan" s
WHERE s."modelVersion" IS NOT NULL
GROUP BY s."modelVersion"
ON CONFLICT ("version") DO NOTHING;

-- Repair orphaned reviewer references before adding the foreign key.
UPDATE "PhishingReport" p
SET "reviewedById" = NULL
WHERE p."reviewedById" IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM "User" u WHERE u."id" = p."reviewedById");

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'PhishingReport_reviewedById_fkey') THEN
    ALTER TABLE "PhishingReport"
      ADD CONSTRAINT "PhishingReport_reviewedById_fkey"
      FOREIGN KEY ("reviewedById") REFERENCES "User"("id")
      ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS "PhishingReport_reviewedById_reviewedAt_idx"
  ON "PhishingReport"("reviewedById", "reviewedAt");

CREATE INDEX IF NOT EXISTS "Scan_userId_verdict_createdAt_idx"
  ON "Scan"("userId", "verdict", "createdAt");

ALTER TABLE "User"
  ALTER COLUMN "updatedAt" SET DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE "PhishingReport"
  ALTER COLUMN "updatedAt" SET DEFAULT CURRENT_TIMESTAMP;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'Scan_riskScore_range_chk') THEN
    ALTER TABLE "Scan" ADD CONSTRAINT "Scan_riskScore_range_chk"
      CHECK ("riskScore" IS NULL OR ("riskScore" >= 0 AND "riskScore" <= 100)) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ScanResult_mlProbability_range_chk') THEN
    ALTER TABLE "ScanResult" ADD CONSTRAINT "ScanResult_mlProbability_range_chk"
      CHECK ("mlProbability" IS NULL OR ("mlProbability" >= 0 AND "mlProbability" <= 1)) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'AuthSession_expiry_after_creation_chk') THEN
    ALTER TABLE "AuthSession" ADD CONSTRAINT "AuthSession_expiry_after_creation_chk"
      CHECK ("expiresAt" > "createdAt") NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'Scan_url_length_chk') THEN
    ALTER TABLE "Scan" ADD CONSTRAINT "Scan_url_length_chk"
      CHECK (char_length("url") BETWEEN 1 AND 4096 AND char_length("normalizedUrl") BETWEEN 1 AND 4096) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'PhishingReport_url_length_chk') THEN
    ALTER TABLE "PhishingReport" ADD CONSTRAINT "PhishingReport_url_length_chk"
      CHECK (char_length("url") BETWEEN 1 AND 4096) NOT VALID;
  END IF;
END $$;
