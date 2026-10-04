import rateLimit from 'express-rate-limit'
import { env } from '../config/env.js'

const base = { standardHeaders: 'draft-8' as const, legacyHeaders: false, skipSuccessfulRequests: false }

export const apiRateLimit = rateLimit({
  ...base,
  windowMs: env.API_RATE_LIMIT_WINDOW_MS,
  limit: env.API_RATE_LIMIT_MAX,
  skip: (req) => ['/api/v1/live', '/api/v1/health', '/api/v1/ready'].includes(req.path),
  message: { error: { code: 'API_RATE_LIMITED', message: 'Too many requests. Please try again shortly.' } },
})

export const scanRateLimit = rateLimit({
  ...base,
  windowMs: env.API_RATE_LIMIT_WINDOW_MS,
  limit: env.SCAN_RATE_LIMIT_MAX,
  message: { error: { code: 'SCAN_RATE_LIMITED', message: 'Too many scans were requested from this network. Please try again later.' } },
})

export const reportRateLimit = rateLimit({
  ...base,
  windowMs: 15 * 60_000,
  limit: env.REPORT_RATE_LIMIT_MAX,
  message: { error: { code: 'REPORT_RATE_LIMITED', message: 'Too many reports were submitted. Please try again later.' } },
})

export const adminWriteRateLimit = rateLimit({
  ...base,
  windowMs: 60_000,
  limit: env.ADMIN_WRITE_RATE_LIMIT_MAX,
  message: { error: { code: 'ADMIN_RATE_LIMITED', message: 'Too many administrative changes were requested. Please try again shortly.' } },
})
