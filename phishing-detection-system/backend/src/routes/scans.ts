import { Router } from 'express'
import { createScan } from '../controllers/scans.js'
import { optionalAuth, requireCsrfIfAuthenticated } from '../middleware/auth.js'
import { scanRateLimit } from '../middleware/rateLimits.js'

export const scansRouter = Router()
scansRouter.post('/', scanRateLimit, optionalAuth, requireCsrfIfAuthenticated, createScan)
