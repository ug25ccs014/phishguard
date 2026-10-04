type Level = 'info' | 'warn' | 'error'

const SENSITIVE_KEY_RE = /password|passwd|token|secret|authorization|cookie|api[_-]?key|database[_-]?url/i
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi
const QUERY_SECRET_RE = /([?&](?:token|access[_-]?token|refresh[_-]?token|password|passwd|secret|api[_-]?key|session(?:[_-]?id)?|sid|otp|verification[_-]?code|reset[_-]?token)=)[^&#\s]+/gi
const DB_URL_CREDENTIAL_RE = /(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/([^:/\s]+):([^@\s]+)@/gi

function sanitizeString(value: string): string {
  return value
    .replace(BEARER_RE, 'Bearer [REDACTED]')
    .replace(QUERY_SECRET_RE, '$1[REDACTED]')
    .replace(DB_URL_CREDENTIAL_RE, '$1://[REDACTED]:[REDACTED]@')
}

function sanitize(value: unknown, key = ''): unknown {
  if (SENSITIVE_KEY_RE.test(key)) return '[REDACTED]'
  if (typeof value === 'string') return sanitizeString(value)
  if (Array.isArray(value)) return value.map((item) => sanitize(item, key))
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, sanitize(childValue, childKey)]))
  }
  return value
}

function write(level: Level, message: string, meta: Record<string, unknown> = {}) {
  const line = JSON.stringify({ timestamp: new Date().toISOString(), level, message: sanitizeString(message), ...sanitize(meta) as Record<string, unknown> })
  if (level === 'error') console.error(line)
  else console.log(line)
}

export const logger = {
  info: (message: string, meta?: Record<string, unknown>) => write('info', message, meta),
  warn: (message: string, meta?: Record<string, unknown>) => write('warn', message, meta),
  error: (message: string, meta?: Record<string, unknown>) => write('error', message, meta),
}
