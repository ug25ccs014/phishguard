-- Step 3: threat intelligence and enrichment persistence
ALTER TABLE "ScanResult" ADD COLUMN IF NOT EXISTS "threatIntelligenceJson" JSONB;
ALTER TABLE "ScanResult" ADD COLUMN IF NOT EXISTS "domainIntelligenceJson" JSONB;
ALTER TABLE "ScanResult" ADD COLUMN IF NOT EXISTS "riskBreakdownJson" JSONB;
ALTER TABLE "ScanResult" ADD COLUMN IF NOT EXISTS "coverageJson" JSONB;

ALTER TABLE "ThreatIntelligenceRecord" ADD COLUMN IF NOT EXISTS "scanId" TEXT;
CREATE INDEX IF NOT EXISTS "ThreatIntelligenceRecord_scanId_idx" ON "ThreatIntelligenceRecord"("scanId");

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ThreatIntelligenceRecord_scanId_fkey') THEN
    ALTER TABLE "ThreatIntelligenceRecord" ADD CONSTRAINT "ThreatIntelligenceRecord_scanId_fkey"
      FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;
