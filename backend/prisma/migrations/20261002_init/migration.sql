-- PhishGuard initial schema (Step 1 baseline).
-- Later migrations extend this schema with ML, intelligence and workspace fields.

CREATE TYPE "UserRole" AS ENUM ('USER', 'ADMIN');
CREATE TYPE "RiskLevel" AS ENUM ('LOW_RISK', 'SUSPICIOUS', 'HIGH_RISK', 'LIKELY_PHISHING', 'KNOWN_MALICIOUS');
CREATE TYPE "ReportStatus" AS ENUM ('PENDING', 'REVIEWED', 'CONFIRMED', 'REJECTED');

CREATE TABLE "User" (
  "id" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "passwordHash" TEXT NOT NULL,
  "role" "UserRole" NOT NULL DEFAULT 'USER',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Scan" (
  "id" TEXT NOT NULL,
  "userId" TEXT,
  "url" TEXT NOT NULL,
  "normalizedUrl" TEXT NOT NULL,
  "domain" TEXT NOT NULL,
  "verdict" "RiskLevel",
  "riskScore" INTEGER,
  "modelVersion" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ScanResult" (
  "id" TEXT NOT NULL,
  "scanId" TEXT NOT NULL,
  "mlSignal" TEXT,
  "heuristicSignal" TEXT,
  "threatIntelligenceSignal" TEXT,
  "domainSignal" TEXT,
  "dnsTlsSignal" TEXT,
  "reasonsJson" JSONB,
  "recommendation" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ScanResult_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ThreatIntelligenceRecord" (
  "id" TEXT NOT NULL,
  "url" TEXT NOT NULL,
  "source" TEXT NOT NULL,
  "status" TEXT NOT NULL,
  "firstSeen" TIMESTAMP(3),
  "lastSeen" TIMESTAMP(3),
  "rawSummary" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ThreatIntelligenceRecord_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "PhishingReport" (
  "id" TEXT NOT NULL,
  "userId" TEXT,
  "url" TEXT NOT NULL,
  "category" TEXT NOT NULL,
  "description" TEXT,
  "status" "ReportStatus" NOT NULL DEFAULT 'PENDING',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "PhishingReport_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ModelVersion" (
  "id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "version" TEXT NOT NULL,
  "dataset" TEXT,
  "featureVersion" TEXT,
  "metrics" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ModelVersion_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE INDEX "User_createdAt_idx" ON "User"("createdAt");
CREATE INDEX "Scan_userId_createdAt_idx" ON "Scan"("userId", "createdAt");
CREATE INDEX "Scan_domain_idx" ON "Scan"("domain");
CREATE UNIQUE INDEX "ScanResult_scanId_key" ON "ScanResult"("scanId");
CREATE INDEX "ThreatIntelligenceRecord_url_source_idx" ON "ThreatIntelligenceRecord"("url", "source");
CREATE INDEX "ThreatIntelligenceRecord_createdAt_idx" ON "ThreatIntelligenceRecord"("createdAt");
CREATE INDEX "PhishingReport_status_createdAt_idx" ON "PhishingReport"("status", "createdAt");
CREATE UNIQUE INDEX "ModelVersion_version_key" ON "ModelVersion"("version");
CREATE INDEX "ModelVersion_createdAt_idx" ON "ModelVersion"("createdAt");

ALTER TABLE "Scan"
  ADD CONSTRAINT "Scan_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ScanResult"
  ADD CONSTRAINT "ScanResult_scanId_fkey"
  FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PhishingReport"
  ADD CONSTRAINT "PhishingReport_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
