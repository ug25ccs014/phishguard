import { z } from 'zod'

const SENSITIVE_QUERY_TERMS = ['token', 'accesstoken', 'refreshtoken', 'authentication', 'auth', 'password', 'passwd', 'passcode', 'secret', 'apikey', 'session', 'sessionid', 'sid', 'otp', 'onetimecode', 'verificationcode', 'resetcode', 'resettoken', 'email'] as const

function isSensitiveQueryKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '')
  return SENSITIVE_QUERY_TERMS.some((term) => normalized === term || normalized.includes(term))
}

const urlSchema = z.string().trim().min(1).max(4096).refine((value) => {
  try {
    const parsed = new URL(value)
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && !parsed.username && !parsed.password
  } catch {
    return false
  }
}, 'Only valid HTTP/HTTPS URLs are accepted.')

export const scanInputSchema = z.object({ url: urlSchema })

export function normalizeUrl(value: string): string {
  const parsed = new URL(value.trim())
  parsed.hash = ''
  return parsed.toString()
}

export function sanitizeUrlForStorage(value: string): string {
  const parsed = new URL(normalizeUrl(value))
  const sanitized = new URLSearchParams()
  for (const [key, queryValue] of parsed.searchParams.entries()) {
    sanitized.append(key, isSensitiveQueryKey(key) ? '[REDACTED]' : queryValue)
  }
  parsed.search = sanitized.toString()
  return parsed.toString()
}

export function hasSensitiveQueryParameter(value: string): boolean {
  try {
    const parsed = new URL(value)
    return Array.from(parsed.searchParams.keys()).some((key) => isSensitiveQueryKey(key))
  } catch {
    return false
  }
}
