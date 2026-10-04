import 'dotenv/config'
import { z } from 'zod'

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  HOST: z.string().default('0.0.0.0'),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(0),
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  DATABASE_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32),
  AUTH_COOKIE_NAME: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/).default('phishguard_access'),
  CSRF_COOKIE_NAME: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/).default('phishguard_csrf'),
  AUTH_COOKIE_SAMESITE: z.enum(['lax', 'strict', 'none']).default('lax'),
  AUTH_COOKIE_SECURE: z.enum(['true', 'false']).optional(),
  COOKIE_DOMAIN: z.string().optional(),
  AUTH_SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(24 * 30).default(12),
  LOG_LEVEL: z.string().default('info'),
  APP_VERSION: z.string().min(1).default('0.5.0'),
  JSON_BODY_LIMIT: z.string().default('32kb'),
  API_RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).max(60 * 60 * 1000).default(60_000),
  API_RATE_LIMIT_MAX: z.coerce.number().int().min(10).max(5000).default(100),
  SCAN_RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(500).default(20),
  REPORT_RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(200).default(10),
  ADMIN_WRITE_RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(500).default(60),
  ML_SERVICE_URL: z.string().url().default('http://localhost:8000'),
  ML_SERVICE_TIMEOUT_MS: z.coerce.number().int().min(100).max(60000).default(5000),
  APP_USER_AGENT: z.string().min(1).default('PhishGuard/0.5.0'),
  THREAT_PROVIDER_TIMEOUT_MS: z.coerce.number().int().min(250).max(15000).default(3500),
  THREAT_PROVIDER_MAX_RESPONSE_BYTES: z.coerce.number().int().min(16384).max(2_000_000).default(512_000),
  PHISHTANK_ENABLED: z.enum(['true', 'false']).default('true').transform((value) => value === 'true'),
  PHISHTANK_API_URL: z.string().url().default('http://checkurl.phishtank.com/checkurl/'),
  PHISHTANK_APP_KEY: z.string().optional(),
  PHISHTANK_USER_AGENT: z.string().min(1).default('phishguard-security-scanner/0.5.0'),
  OPENPHISH_ENABLED: z.enum(['true', 'false']).default('true').transform((value) => value === 'true'),
  OPENPHISH_FEED_URL: z.string().url().default('https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'),
  OPENPHISH_CACHE_TTL_MS: z.coerce.number().int().min(60000).max(7 * 24 * 60 * 60 * 1000).default(12 * 60 * 60 * 1000),
  THREAT_RESULT_CACHE_TTL_MS: z.coerce.number().int().min(10000).max(24 * 60 * 60 * 1000).default(5 * 60 * 1000),
  THREAT_RESULT_CACHE_MAX_ENTRIES: z.coerce.number().int().min(100).max(10000).default(2000),
  OPENPHISH_USER_AGENT: z.string().min(1).default('PhishGuard/0.5.0'),
  GOOGLE_WEB_RISK_API_KEY: z.string().optional(),
  GOOGLE_WEB_RISK_THREAT_TYPES: z.string().default('SOCIAL_ENGINEERING,MALWARE,UNWANTED_SOFTWARE'),
  VIRUSTOTAL_ENABLED: z.enum(['true', 'false']).default('false').transform((value) => value === 'true'),
  VIRUSTOTAL_API_KEY: z.string().optional(),
  RDAP_TIMEOUT_MS: z.coerce.number().int().min(250).max(15000).default(3500),
  RDAP_MAX_RESPONSE_BYTES: z.coerce.number().int().min(16384).max(2_000_000).default(1_000_000),
  RDAP_BOOTSTRAP_CACHE_TTL_MS: z.coerce.number().int().min(60000).max(7 * 24 * 60 * 60 * 1000).default(24 * 60 * 60 * 1000),
  DNS_TIMEOUT_MS: z.coerce.number().int().min(250).max(10000).default(2500),
  TLS_TIMEOUT_MS: z.coerce.number().int().min(250).max(10000).default(2500),
})

export const env = envSchema.superRefine((value, ctx) => {
  if (value.AUTH_COOKIE_SAMESITE === 'none' && value.AUTH_COOKIE_SECURE !== 'true') {
    ctx.addIssue({ code: 'custom', path: ['AUTH_COOKIE_SECURE'], message: 'AUTH_COOKIE_SECURE=true is required when AUTH_COOKIE_SAMESITE=none.' })
  }
  if (value.NODE_ENV === 'production') {
    if (value.AUTH_COOKIE_SECURE !== 'true') {
      ctx.addIssue({ code: 'custom', path: ['AUTH_COOKIE_SECURE'], message: 'AUTH_COOKIE_SECURE=true is required in production.' })
    }
    if (/(^|[, ])https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?($|[, ])/i.test(value.CORS_ORIGIN)) {
      ctx.addIssue({ code: 'custom', path: ['CORS_ORIGIN'], message: 'Production CORS_ORIGIN cannot contain localhost or loopback origins.' })
    }
    if (/^replace-with-a-long-random-secret/i.test(value.JWT_SECRET) || value.JWT_SECRET.length < 48) {
      ctx.addIssue({ code: 'custom', path: ['JWT_SECRET'], message: 'Production JWT_SECRET must be a non-placeholder secret of at least 48 characters.' })
    }
  }
}).parse(process.env)
