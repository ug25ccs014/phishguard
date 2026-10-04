import { Prisma, RiskLevel } from '@prisma/client'
import { logger } from '../utils/logger.js'
import { prisma } from '../lib/prisma.js'
import { normalizeUrl, sanitizeUrlForStorage } from '../validators/url.js'
import { predictWithML, type MLResponse } from './mlClient.js'
import { collectDomainIntelligence } from './intelligence/domainIntelligence.js'
import { collectThreatIntelligence } from './intelligence/threatIntel.js'
import { calculateRisk, scoreHeuristics } from './intelligence/riskEngine.js'
import type { DomainIntelligenceAssessment, ThreatIntelligenceAssessment } from './intelligence/types.js'

export type ScanAssessment = {
  id: string
  url: string
  normalizedUrl: string
  domain: string
  verdict: 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK' | 'LIKELY PHISHING' | 'KNOWN MALICIOUS'
  riskScore: number
  scannedAt: string
  modelVersion: string
  signals: {
    ml: string
    heuristics: string
    threatIntelligence: string
    domain: string
    dnsTls: string
  }
  reasons: string[]
  recommendation: string
  methodology: string
  ml: MLResponse
  threatIntelligence: ThreatIntelligenceAssessment
  domainIntelligence: DomainIntelligenceAssessment
  riskBreakdown: ReturnType<typeof calculateRisk>['signals']
  persistence: 'PERSISTED' | 'NOT_PERSISTED'
}

function toPrismaRiskLevel(verdict: ScanAssessment['verdict']): RiskLevel {
  const mapping: Record<ScanAssessment['verdict'], RiskLevel> = {
    'LOW RISK': RiskLevel.LOW_RISK,
    'SUSPICIOUS': RiskLevel.SUSPICIOUS,
    'HIGH RISK': RiskLevel.HIGH_RISK,
    'LIKELY PHISHING': RiskLevel.LIKELY_PHISHING,
    'KNOWN MALICIOUS': RiskLevel.KNOWN_MALICIOUS,
  }
  return mapping[verdict]
}

function hostnameFromUrl(url: string): string { return new URL(url).hostname }

function toDateOrNull(value: string | null | undefined): Date | null {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

function toSignalLabel(score: number): string {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH RISK'
  if (score >= 30) return 'MODERATE'
  return 'LOW RISK'
}

function summarizeThreat(threat: ThreatIntelligenceAssessment): string {
  if (threat.status === 'BLOCKED') return 'BLOCKED — external lookup skipped for privacy/safety'
  if (threat.status === 'UNAVAILABLE') return 'UNAVAILABLE'
  if (threat.knownMalicious) return `MATCHED — ${threat.matchedSources.join(', ')}`
  if (threat.suspiciousSources.length) return `SUSPICIOUS — ${threat.suspiciousSources.join(', ')}`
  return `NO MATCH — ${threat.availableProviders}/${threat.configuredProviders} configured providers`
}

function summarizeDomain(domain: DomainIntelligenceAssessment): string {
  if (domain.status === 'BLOCKED') return 'BLOCKED — private/reserved destination'
  if (domain.status === 'UNAVAILABLE') return 'UNAVAILABLE'
  if (domain.rdap.daysOld !== null && domain.rdap.daysOld < 30) return `YOUNG DOMAIN — ${domain.rdap.daysOld} days`
  return domain.rdap.status === 'AVAILABLE' ? 'AVAILABLE' : 'PARTIAL'
}

function summarizeDnsTls(domain: DomainIntelligenceAssessment): string {
  if (domain.status === 'BLOCKED') return 'BLOCKED'
  if (domain.tls.status === 'AVAILABLE') return domain.tls.authorized ? 'DNS OK · TLS VALID' : 'DNS OK · TLS WARNING'
  if (domain.dns.status === 'AVAILABLE') return 'DNS AVAILABLE · TLS UNAVAILABLE'
  return 'PARTIAL / UNAVAILABLE'
}

export async function scanUrl(inputUrl: string, userId?: string): Promise<ScanAssessment> {
  const normalizedUrl = normalizeUrl(inputUrl)
  const safeStoredUrl = sanitizeUrlForStorage(normalizedUrl)
  const parsed = new URL(normalizedUrl)
  const domain = hostnameFromUrl(normalizedUrl)
  const [ml, domainResult] = await Promise.all([
    predictWithML(normalizedUrl),
    collectDomainIntelligence(domain, parsed.protocol),
  ])
  const heuristic = scoreHeuristics(ml.features)

  const threatResult = await collectThreatIntelligence(normalizedUrl, {
    blockExternalLookup: domainResult.status === 'BLOCKED' || domainResult.dns.privateAddresses.length > 0,
    blockReason: domainResult.status === 'BLOCKED'
      ? 'External threat-intelligence lookup was blocked because domain enrichment identified a private or reserved destination.'
      : undefined,
  })

  const risk = calculateRisk(ml.phishingProbability, heuristic, threatResult, domainResult)

  const assessment: ScanAssessment = {
    id: `scan-${crypto.randomUUID()}`,
    url: safeStoredUrl,
    normalizedUrl: safeStoredUrl,
    domain,
    verdict: risk.verdict,
    riskScore: risk.riskScore,
    scannedAt: new Date().toISOString(),
    modelVersion: ml.modelVersion,
    signals: {
      ml: toSignalLabel(ml.phishingProbability * 100),
      heuristics: heuristic.level,
      threatIntelligence: summarizeThreat(threatResult),
      domain: summarizeDomain(domainResult),
      dnsTls: summarizeDnsTls(domainResult),
    },
    reasons: risk.reasons,
    recommendation: risk.recommendation,
    methodology: risk.methodology,
    ml,
    threatIntelligence: threatResult,
    domainIntelligence: domainResult,
    riskBreakdown: risk.signals,
    persistence: 'NOT_PERSISTED',
  }

  try {
    const createdScan = await prisma.$transaction(async (tx) => {
      await tx.modelVersion.upsert({
        where: { version: ml.modelVersion },
        update: { name: ml.modelName, featureVersion: ml.featureVersion },
        create: { name: ml.modelName, version: ml.modelVersion, featureVersion: ml.featureVersion },
      })

      const scan = await tx.scan.create({
        data: {
          url: safeStoredUrl,
          normalizedUrl: safeStoredUrl,
          domain,
          verdict: toPrismaRiskLevel(risk.verdict),
          riskScore: risk.riskScore,
          modelVersion: ml.modelVersion,
          userId: userId ?? null,
          result: {
            create: {
              mlSignal: assessment.signals.ml,
              heuristicSignal: assessment.signals.heuristics,
              threatIntelligenceSignal: assessment.signals.threatIntelligence,
              domainSignal: assessment.signals.domain,
              dnsTlsSignal: assessment.signals.dnsTls,
              mlProbability: ml.phishingProbability,
              featuresJson: ml.features,
              modelName: ml.modelName,
              featureVersion: ml.featureVersion,
              topModelFeaturesJson: ml.topModelFeatures,
              methodology: assessment.methodology,
              reasonsJson: assessment.reasons,
              recommendation: assessment.recommendation,
              threatIntelligenceJson: threatResult,
              domainIntelligenceJson: domainResult,
              riskBreakdownJson: risk.signals,
              coverageJson: {
                threatIntelligence: { available: threatResult.availableProviders, configured: threatResult.configuredProviders, coveragePercent: threatResult.coveragePercent },
                domainIntelligence: domainResult.status,
              },
            },
          },
        },
      })

      if (threatResult.providers.length) {
        await tx.threatIntelligenceRecord.createMany({
          data: threatResult.providers.map((provider) => ({
            scanId: scan.id,
            url: safeStoredUrl,
            source: provider.provider,
            status: provider.status,
            firstSeen: toDateOrNull(provider.firstSeen),
            lastSeen: toDateOrNull(provider.lastSeen),
            rawSummary: {
              summary: provider.summary,
              checkedAt: provider.checkedAt,
              threatTypes: provider.threatTypes ?? [],
              matched: provider.matched,
              details: provider.details ?? {},
            },
          })),
        })
      }

      return scan
    })

    return { ...assessment, id: createdScan.id, persistence: 'PERSISTED' }

  } catch (error) {
    const isAvailabilityFailure =
      (error instanceof Prisma.PrismaClientKnownRequestError && /^P10\d{2}$/.test(error.code)) ||
      error instanceof Prisma.PrismaClientInitializationError ||
      (error instanceof Error && /database server|database is unavailable|connection.*closed|connection.*refused|can't reach/i.test(error.message))

    if (!isAvailabilityFailure) throw error

    logger.warn('Scan persistence unavailable; returning live multi-signal result.', {
      error: error instanceof Error ? error.message : String(error),
    })
    return assessment
  }
}
