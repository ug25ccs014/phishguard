import type { RequestHandler } from 'express'
import { Prisma, RiskLevel, ReportStatus, UserRole } from '@prisma/client'
import { prisma } from '../lib/prisma.js'
import { adminReportsQuerySchema, idParamSchema, reportCreateSchema, reportStatusSchema, scanQuerySchema } from '../validators/workspace.js'
import { getProviderConfiguration } from '../services/intelligence/threatIntel.js'
import { readJsonWithLimit } from '../services/intelligence/http.js'
import { canDeleteScan } from '../services/authorization.js'
import { env } from '../config/env.js'

function mapRisk(value: RiskLevel | null): string | null {
  if (!value) return null
  return ({ LOW_RISK: 'LOW RISK', SUSPICIOUS: 'SUSPICIOUS', HIGH_RISK: 'HIGH RISK', LIKELY_PHISHING: 'LIKELY PHISHING', KNOWN_MALICIOUS: 'KNOWN MALICIOUS' } as Record<RiskLevel,string>)[value]
}

export const listScans: RequestHandler = async (req, res, next) => {
  try {
    const q = scanQuerySchema.parse(req.query)
    const where: Prisma.ScanWhereInput = { userId: req.authUser!.id }
    if (q.search) where.OR = [{ url: { contains: q.search, mode: 'insensitive' } }, { domain: { contains: q.search, mode: 'insensitive' } }]
    if (q.verdict) where.verdict = ({ 'LOW RISK': RiskLevel.LOW_RISK, SUSPICIOUS: RiskLevel.SUSPICIOUS, 'HIGH RISK': RiskLevel.HIGH_RISK, 'LIKELY PHISHING': RiskLevel.LIKELY_PHISHING, 'KNOWN MALICIOUS': RiskLevel.KNOWN_MALICIOUS } as Record<string,RiskLevel>)[q.verdict]
    const [items, total] = await prisma.$transaction([
      prisma.scan.findMany({ where, orderBy: { createdAt: 'desc' }, skip: (q.page - 1) * q.pageSize, take: q.pageSize, select: { id: true, url: true, verdict: true, riskScore: true, createdAt: true, domain: true, modelVersion: true } }),
      prisma.scan.count({ where }),
    ])
    return res.json({ items: items.map((item) => ({ id: item.id, url: item.url, domain: item.domain, verdict: mapRisk(item.verdict), riskScore: item.riskScore ?? 0, scannedAt: item.createdAt.toISOString(), modelVersion: item.modelVersion })), pagination: { page: q.page, pageSize: q.pageSize, total, totalPages: Math.max(1, Math.ceil(total / q.pageSize)) } })
  } catch (error) { return next(error) }
}

export const getScan: RequestHandler = async (req, res, next) => {
  try {
    const { id } = idParamSchema.parse(req.params)
    const where: Prisma.ScanWhereInput = req.authUser!.role === UserRole.ADMIN ? { id } : { id, userId: req.authUser!.id }
    const scan = await prisma.scan.findFirst({ where, include: { result: true, threatIntelligenceRecords: true } })
    if (!scan) return res.status(404).json({ error: { code: 'SCAN_NOT_FOUND', message: 'Scan not found.' } })
    if (!scan.result) return res.status(409).json({ error: { code: 'SCAN_RESULT_MISSING', message: 'This scan does not have a stored result.' } })
    const result = scan.result
    const storedThreat = (result.threatIntelligenceJson && typeof result.threatIntelligenceJson === 'object' ? result.threatIntelligenceJson : { status: 'UNAVAILABLE', knownMalicious: false, matchedSources: [], suspiciousSources: [], signalScore: 0, providers: [], availableProviders: 0, configuredProviders: 0, coveragePercent: 0 })
    const storedDomain = (result.domainIntelligenceJson && typeof result.domainIntelligenceJson === 'object' ? result.domainIntelligenceJson : { status: 'UNAVAILABLE', hostname: scan.domain, signalScore: 0, reasons: [], rdap: { status: 'UNAVAILABLE', rdapServer: null, registrableDomain: null, registrar: null, statuses: [], nameservers: [], createdAt: null, updatedAt: null, expiresAt: null, daysOld: null, score: 0, reasons: [] }, dns: { status: 'UNAVAILABLE', ipv4: [], ipv6: [], mx: [], ns: [], privateAddresses: [], publicAddresses: [], noAddressRecord: false, score: 0, reasons: [] }, tls: { status: 'NOT_APPLICABLE', authorized: null, authorizationError: null, subject: null, issuer: null, validFrom: null, validTo: null, daysRemaining: null, score: 0, reasons: [] } })
    const storedBreakdown = Array.isArray(result.riskBreakdownJson) ? result.riskBreakdownJson : []
    const response = {
      id: scan.id, url: scan.url, normalizedUrl: scan.normalizedUrl, domain: scan.domain, verdict: mapRisk(scan.verdict), riskScore: scan.riskScore ?? 0, scannedAt: scan.createdAt.toISOString(), modelVersion: scan.modelVersion ?? result.modelName ?? 'unknown',
      signals: { ml: result.mlSignal ?? 'UNAVAILABLE', heuristics: result.heuristicSignal ?? 'UNAVAILABLE', threatIntelligence: result.threatIntelligenceSignal ?? 'UNAVAILABLE', domain: result.domainSignal ?? 'UNAVAILABLE', dnsTls: result.dnsTlsSignal ?? 'UNAVAILABLE' },
      reasons: Array.isArray(result.reasonsJson) ? result.reasonsJson : [], recommendation: result.recommendation ?? 'Treat the result as a risk assessment and independently verify important destinations.', methodology: result.methodology ?? 'Stored multi-signal security assessment.', ml: { prediction: Number(result.mlProbability ?? 0) >= 0.5 ? 1 : 0, label: Number(result.mlProbability ?? 0) >= 0.5 ? 'PHISHING' : 'LEGITIMATE', phishingProbability: Number(result.mlProbability ?? 0), legitimateProbability: 1 - Number(result.mlProbability ?? 0), featureVersion: result.featureVersion ?? 'unknown', modelVersion: scan.modelVersion ?? 'unknown', modelName: result.modelName ?? 'unknown', features: (result.featuresJson && typeof result.featuresJson === 'object' ? result.featuresJson : {}) as Record<string, number>, topModelFeatures: (Array.isArray(result.topModelFeaturesJson) ? result.topModelFeaturesJson : []) as Array<{ feature: string; importance: number }>, probabilityCalibrated: false, },
      threatIntelligence: storedThreat, domainIntelligence: storedDomain, riskBreakdown: storedBreakdown, persistence: 'PERSISTED',
    }
    return res.json(response)
  } catch (error) { return next(error) }
}

export const deleteScan: RequestHandler = async (req, res, next) => {
  try {
    const { id } = idParamSchema.parse(req.params)
    const scan = await prisma.scan.findUnique({ where: { id }, select: { id: true, userId: true } })
    if (!scan || !canDeleteScan(req.authUser!.id, scan.userId)) return res.status(404).json({ error: { code: 'SCAN_NOT_FOUND', message: 'Scan not found.' } })
    await prisma.scan.delete({ where: { id: scan.id } })
    return res.status(204).send()
  } catch (error) { return next(error) }
}

export const dashboard: RequestHandler = async (req, res, next) => {
  try {
    const userId = req.authUser!.id
    const [total, low, suspicious, high, recent] = await prisma.$transaction([
      prisma.scan.count({ where: { userId } }),
      prisma.scan.count({ where: { userId, verdict: RiskLevel.LOW_RISK } }),
      prisma.scan.count({ where: { userId, verdict: RiskLevel.SUSPICIOUS } }),
      prisma.scan.count({ where: { userId, verdict: { in: [RiskLevel.HIGH_RISK, RiskLevel.LIKELY_PHISHING, RiskLevel.KNOWN_MALICIOUS] } } }),
      prisma.scan.findMany({ where: { userId }, orderBy: { createdAt: 'desc' }, take: 8, select: { id: true, url: true, verdict: true, riskScore: true, createdAt: true } }),
    ])
    const now = new Date(); const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 6))
    const trend = await Promise.all(Array.from({ length: 7 }, (_, index) => { const day = new Date(start); day.setUTCDate(start.getUTCDate() + index); const next = new Date(day); next.setUTCDate(day.getUTCDate() + 1); return prisma.scan.count({ where: { userId, createdAt: { gte: day, lt: next } } }).then((scans) => ({ date: day.toISOString().slice(0,10), scans })) }))
    return res.json({ stats: { total, lowRisk: low, suspicious, highRisk: high }, trend, recent: recent.map((item) => ({ id: item.id, url: item.url, verdict: mapRisk(item.verdict), riskScore: item.riskScore ?? 0, scannedAt: item.createdAt.toISOString() })) })
  } catch (error) { return next(error) }
}

export const createReport: RequestHandler = async (req, res, next) => {
  try {
    const input = reportCreateSchema.parse(req.body)
    const report = await prisma.phishingReport.create({ data: { userId: req.authUser!.id, url: input.url, category: input.category, description: input.description || null } })
    return res.status(201).json({ id: report.id, status: report.status, createdAt: report.createdAt.toISOString() })
  } catch (error) { return next(error) }
}

export const listMyReports: RequestHandler = async (req, res, next) => {
  try {
    const reports = await prisma.phishingReport.findMany({ where: { userId: req.authUser!.id }, orderBy: { createdAt: 'desc' }, take: 30 })
    return res.json({ items: reports })
  } catch (error) { return next(error) }
}

export const adminOverview: RequestHandler = async (_req, res, next) => {
  try {
    const [users, scans, low, suspicious, high, openReports, recentReports] = await prisma.$transaction([
      prisma.user.count(),
      prisma.scan.count(),
      prisma.scan.count({ where: { verdict: RiskLevel.LOW_RISK } }),
      prisma.scan.count({ where: { verdict: RiskLevel.SUSPICIOUS } }),
      prisma.scan.count({ where: { verdict: { in: [RiskLevel.HIGH_RISK, RiskLevel.LIKELY_PHISHING, RiskLevel.KNOWN_MALICIOUS] } } }),
      prisma.phishingReport.count({ where: { status: { in: [ReportStatus.PENDING, ReportStatus.REVIEWED] } } }),
      prisma.phishingReport.findMany({ orderBy: { createdAt: 'desc' }, take: 8, select: { id: true, url: true, category: true, status: true, createdAt: true } }),
    ])
    const now = new Date(); const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 6))
    const trend = await Promise.all(Array.from({ length: 7 }, (_, index) => { const day = new Date(start); day.setUTCDate(start.getUTCDate() + index); const next = new Date(day); next.setUTCDate(day.getUTCDate() + 1); return Promise.all([prisma.scan.count({ where: { createdAt: { gte: day, lt: next }, verdict: { in: [RiskLevel.HIGH_RISK, RiskLevel.LIKELY_PHISHING, RiskLevel.KNOWN_MALICIOUS] } } }), prisma.scan.count({ where: { createdAt: { gte: day, lt: next }, verdict: RiskLevel.SUSPICIOUS } })]).then(([phishing, suspicious]) => ({ date: day.toISOString().slice(0,10), phishing, suspicious })) }))
    return res.json({ stats: { users, scans, lowRisk: low, suspicious, highRisk: high, openReports }, trend, recentReports: recentReports.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() })) })
  } catch (error) { return next(error) }
}

export const adminReports: RequestHandler = async (req, res, next) => {
  try {
    const q = adminReportsQuerySchema.parse(req.query)
    const reports = await prisma.phishingReport.findMany({ where: { ...(q.status ? { status: q.status } : {}), ...(q.search ? { url: { contains: q.search, mode: 'insensitive' } } : {}) }, orderBy: { createdAt: 'desc' }, take: 100, include: { user: { select: { id: true, name: true, email: true } } } })
    return res.json({ items: reports })
  } catch (error) { return next(error) }
}

export const updateAdminReport: RequestHandler = async (req, res, next) => {
  try {
    const { id } = idParamSchema.parse(req.params)
    const input = reportStatusSchema.parse(req.body)
    const isOpen = input.status === ReportStatus.PENDING
    const updated = await prisma.phishingReport.update({ where: { id }, data: { status: input.status, reviewNote: input.reviewNote || null, reviewedAt: isOpen ? null : new Date(), reviewedById: isOpen ? null : req.authUser!.id } })
    return res.json({ report: updated })
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') return res.status(404).json({ error: { code: 'REPORT_NOT_FOUND', message: 'Report not found.' } })
    return next(error)
  }
}

export const adminProviderStatus: RequestHandler = (_req, res) => {
  return res.json({ providers: getProviderConfiguration() })
}

export const adminModelInfo: RequestHandler = async (_req, res) => {
  try {
    const response = await fetch(`${env.ML_SERVICE_URL.replace(/\/$/, '')}/model-info`, { redirect: 'error', signal: AbortSignal.timeout(2500) })
    if (!response.ok) return res.status(503).json({ error: { code: 'ML_METADATA_UNAVAILABLE', message: 'ML model metadata is temporarily unavailable.' } })
    return res.json({ model: await readJsonWithLimit<Record<string, unknown>>(response, 256_000, 2_500) })
  } catch {
    return res.status(503).json({ error: { code: 'ML_METADATA_UNAVAILABLE', message: 'ML model metadata is temporarily unavailable.' } })
  }
}
