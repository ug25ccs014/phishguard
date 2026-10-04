import type { RequestHandler } from 'express'
import { env } from '../config/env.js'
import { prisma } from '../lib/prisma.js'

async function checkMlService(): Promise<boolean> {
  try {
    const response = await fetch(`${env.ML_SERVICE_URL.replace(/\/$/, '')}/ready`, { redirect: 'error', signal: AbortSignal.timeout(Math.min(2500, env.ML_SERVICE_TIMEOUT_MS)) })
    return response.ok
  } catch { return false }
}

export const health: RequestHandler = (_req, res) => {
  res.json({ status: 'ok', service: 'phishing-defense-backend', version: env.APP_VERSION, stage: 'final-release', timestamp: new Date().toISOString() })
}

export const live: RequestHandler = (_req, res) => {
  res.json({ status: 'alive', service: 'phishing-defense-backend', version: env.APP_VERSION })
}

export const ready: RequestHandler = async (_req, res) => {
  const checks = { database: false, mlService: false }
  try { await prisma.$queryRaw`SELECT 1`; checks.database = true } catch { /* readiness remains false */ }
  checks.mlService = await checkMlService()
  const readyNow = checks.database && checks.mlService
  return res.status(readyNow ? 200 : 503).json({ status: readyNow ? 'ready' : 'not_ready', checks, version: env.APP_VERSION })
}

export const meta: RequestHandler = (_req, res) => {
  res.json({
    name: 'PhishGuard',
    version: env.APP_VERSION,
    capabilities: {
      urlScanning: 'real-multi-signal',
      machineLearning: 'enabled',
      threatIntelligence: 'enabled',
      domainIntelligence: 'enabled',
      authentication: 'enabled',
      history: 'enabled',
      reporting: 'enabled',
      admin: 'enabled',
      prevention: 'enabled',
    },
  })
}
