import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import { env } from './config/env.js'
import { errorHandler } from './middleware/errorHandler.js'
import { notFoundHandler } from './middleware/notFound.js'
import { requestLogger } from './middleware/requestLogger.js'
import { requestId } from './middleware/requestId.js'
import { apiRateLimit } from './middleware/rateLimits.js'
import { systemRouter } from './routes/system.js'
import { scansRouter } from './routes/scans.js'
import { authRouter } from './routes/auth.js'
import { workspaceRouter } from './routes/workspace.js'

const allowedOrigins = new Set(env.CORS_ORIGIN.split(',').map((item) => item.trim()).filter(Boolean))

export const app = express()

app.disable('x-powered-by')
app.set('trust proxy', env.TRUST_PROXY_HOPS)

app.use(requestId)
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
  hsts: env.NODE_ENV === 'production' ? undefined : false,
}))

app.use((req, res, next) => {
  const origin = req.header('origin')
  if (origin && !allowedOrigins.has(origin)) {
    return res.status(403).json({ error: { code: 'CORS_ORIGIN_DENIED', message: 'The request origin is not allowed.' } })
  }
  return next()
})

app.use(cors({
  origin: (origin, callback) => callback(null, !origin || allowedOrigins.has(origin)),
  credentials: true,
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  optionsSuccessStatus: 204,
  maxAge: 600,
}))

app.use(apiRateLimit)
app.use(express.json({ limit: env.JSON_BODY_LIMIT, strict: true }))
app.use(express.urlencoded({ extended: false, limit: '16kb' }))
app.use((_, res, next) => {
  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Pragma', 'no-cache')
  next()
})
app.use(requestLogger)

app.get('/', (_req, res) => res.json({ service: 'PhishGuard API', status: 'ok', docs: '/api/v1/meta' }))
app.use('/api/v1', systemRouter)
app.use('/api/v1/auth', authRouter)
app.use('/api/v1/scans', scansRouter)
app.use('/api/v1', workspaceRouter)

app.use(notFoundHandler)
app.use(errorHandler)
