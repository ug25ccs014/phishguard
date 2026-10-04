export function safeInternalDestination(value: unknown, fallback = '/dashboard'): string {
  if (typeof value !== 'string') return fallback
  const candidate = value.trim()
  if (!candidate.startsWith('/') || candidate.startsWith('//') || candidate.includes('://') || candidate.includes('\\') || candidate.includes('\u0000')) return fallback
  return candidate
}
