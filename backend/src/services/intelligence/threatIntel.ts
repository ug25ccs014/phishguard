import { env } from '../../config/env.js'
import net from 'node:net'
import { normalizeUrl } from '../../validators/url.js'
import { fetchWithTimeout, readJsonWithLimit, readTextWithLimit } from './http.js'
import type { ProviderStatus, ThreatIntelProviderResult, ThreatIntelligenceAssessment } from './types.js'

const INTERNAL_HOST_RE = /(^|\.)localhost$|(^|\.)local$|(^|\.)internal$|(^|\.)test$|(^|\.)invalid$|(^|\.)example$|(^|\.)home\.arpa$/i
const OPENPHISH_FEED_URL = env.OPENPHISH_FEED_URL
const GOOGLE_WEB_RISK_URL = 'https://webrisk.googleapis.com/v1/uris:search'
const VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls/'

let openPhishCache: { fetchedAt: number; etag: string | null; lastModified: string | null; urls: Set<string> } | null = null
let openPhishInFlight: Promise<Set<string>> | null = null
const providerResultCache = new Map<string, { expiresAt: number; result: ThreatIntelProviderResult }>()
const providerInFlight = new Map<string, Promise<ThreatIntelProviderResult>>()

function checkedAt(): string { return new Date().toISOString() }

function disabledResult(provider: string, summary: string): ThreatIntelProviderResult {
  return { provider, configured: false, status: 'UNAVAILABLE', matched: false, checkedAt: checkedAt(), summary }
}

function errorResult(provider: string, error: unknown): ThreatIntelProviderResult {
  const message = error instanceof Error ? error.message : 'Unknown provider error.'
  return { provider, configured: true, status: 'ERROR', matched: false, checkedAt: checkedAt(), summary: message.slice(0, 240) }
}

function blockedResult(provider: string, reason: string): ThreatIntelProviderResult {
  return { provider, configured: true, status: 'BLOCKED', matched: false, checkedAt: checkedAt(), summary: reason }
}

function isPrivateOrReservedIp(value: string): boolean {
  const version = net.isIP(value)
  if (version === 4) {
    const [a, b] = value.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && b === 51) || (a === 198 && b === 18) || (a === 198 && b === 19) || (a === 203 && b === 0) || a >= 224
  }
  if (version === 6) {
    const lower = value.toLowerCase()
    const parts = lower.split(':')
    const first = Number.parseInt(parts[0] || '0', 16)
    const second = Number.parseInt(parts[1] || '0', 16)
    const mappedV4 = lower.startsWith('::ffff:') ? lower.slice(7) : ''
    return lower === '::' || lower === '::1' || first === 0 || (first >= 0xfc00 && first <= 0xfdff) || (first >= 0xfe80 && first <= 0xfebf) || first >= 0xff00 || (first === 0x2001 && second === 0x0db8) || (mappedV4 && isPrivateOrReservedIp(mappedV4))
  }
  return true
}

function shouldBlockExternalLookup(url: string): string | null {
  try {
    const parsed = new URL(url)
    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '')
    if (net.isIP(hostname) && isPrivateOrReservedIp(hostname)) return 'External threat-intelligence lookup was blocked for a private or reserved destination.'
    if (!net.isIP(hostname) && INTERNAL_HOST_RE.test(hostname)) return 'External threat-intelligence lookup was blocked for a local or special-use hostname.'

    const sensitiveKey = /(token|access[_-]?token|refresh[_-]?token|auth(?:entication)?|password|passwd|passcode|secret|api[_-]?key|session(?:_?id)?|sid|otp|one[_-]?time[_-]?code|verification[_-]?code|reset[_-]?token|email)/i
    for (const [key] of parsed.searchParams) {
      if (sensitiveKey.test(key)) return 'External threat-intelligence lookup was blocked because the URL contains a potentially sensitive query parameter.'
    }
  } catch {
    return 'External threat-intelligence lookup was blocked because the URL could not be safely parsed.'
  }
  return null
}

async function checkPhishTank(url: string): Promise<ThreatIntelProviderResult> {
  if (!env.PHISHTANK_ENABLED) return disabledResult('PhishTank', 'Provider disabled by configuration.')
  const apiUrl = new URL(env.PHISHTANK_API_URL)
  const sendApplicationKey = Boolean(env.PHISHTANK_APP_KEY && apiUrl.protocol === 'https:')
  const params = new URLSearchParams({ url, format: 'json' })
  if (sendApplicationKey) params.set('app_key', env.PHISHTANK_APP_KEY!)
  try {
    const response = await fetchWithTimeout(env.PHISHTANK_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': env.PHISHTANK_USER_AGENT,
      },
      body: params.toString(),
      redirect: 'error',
    }, env.THREAT_PROVIDER_TIMEOUT_MS)
    if (!response.ok) return { ...errorResult('PhishTank', `HTTP ${response.status}`), status: response.status === 429 || response.status === 509 ? 'RATE_LIMITED' : 'UNAVAILABLE' }
    const payload = await readJsonWithLimit<any>(response, env.THREAT_PROVIDER_MAX_RESPONSE_BYTES, env.THREAT_PROVIDER_TIMEOUT_MS)
    const results = payload?.results ?? {}
    if (!results || typeof results !== 'object' || typeof results.in_database === 'undefined') throw new Error('Provider returned an invalid PhishTank response shape.')
    const inDatabase = results?.in_database === true || results?.in_database === 'true'
    const verified = results?.verified === true || results?.verified === 'y' || results?.verified === 'yes'
    const valid = results?.valid === true || results?.valid === 'y' || results?.valid === 'yes'
    const matched = Boolean(inDatabase && verified && valid)
    const status: ProviderStatus = matched ? 'MATCHED' : inDatabase ? 'SUSPICIOUS' : 'NO_MATCH'
    return {
      provider: 'PhishTank',
      configured: true,
      status,
      matched,
      checkedAt: checkedAt(),
      summary: matched
        ? 'PhishTank reports this URL as a verified and currently valid phish.'
        : inDatabase
          ? 'PhishTank has this URL in its database, but it was not returned as both verified and valid.'
          : 'No phishing record was returned for this URL.',
      firstSeen: results?.submitted_at ?? null,
      lastSeen: results?.verified_at ?? null,
      details: {
        inDatabase: Boolean(inDatabase),
        verified,
        valid,
        phishId: results?.phish_id ? String(results.phish_id) : null,
        applicationKeyUsed: sendApplicationKey,
      },
    }
  } catch (error) {
    return errorResult('PhishTank', error)
  }
}

function comparableUrl(value: string): string {
  try {
    const parsed = new URL(value)
    parsed.hash = ''
    parsed.hostname = parsed.hostname.toLowerCase()
    if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) parsed.port = ''
    if (parsed.pathname !== '/' && parsed.pathname.endsWith('/')) parsed.pathname = parsed.pathname.slice(0, -1)
    return parsed.toString()
  } catch {
    return value.trim()
  }
}

async function loadOpenPhishFeed(): Promise<Set<string>> {
  const now = Date.now()
  if (openPhishCache && now - openPhishCache.fetchedAt < env.OPENPHISH_CACHE_TTL_MS) return openPhishCache.urls
  if (openPhishInFlight) return openPhishInFlight

  openPhishInFlight = (async () => {
    const headers: Record<string, string> = { 'User-Agent': env.OPENPHISH_USER_AGENT }
    if (openPhishCache?.etag) headers['If-None-Match'] = openPhishCache.etag
    if (openPhishCache?.lastModified) headers['If-Modified-Since'] = openPhishCache.lastModified

    const response = await fetchWithTimeout(OPENPHISH_FEED_URL, { headers, redirect: 'error' }, env.THREAT_PROVIDER_TIMEOUT_MS)
    if (response.status === 304 && openPhishCache) {
      openPhishCache = { ...openPhishCache, fetchedAt: Date.now() }
      return openPhishCache.urls
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const body = await readTextWithLimit(response, 3_000_000, env.THREAT_PROVIDER_TIMEOUT_MS)
    const urls = new Set<string>()
    for (const line of body.split(/\r?\n/)) {
      const value = line.trim()
      if (!value) continue
      try {
        const parsed = new URL(value)
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') urls.add(comparableUrl(parsed.toString()))
      } catch {
        // Ignore malformed feed lines.
      }
    }
    if (urls.size === 0) throw new Error('OpenPhish feed returned no valid URL entries.')
    openPhishCache = { fetchedAt: Date.now(), etag: response.headers.get('etag'), lastModified: response.headers.get('last-modified'), urls }
    return urls
  })()

  try { return await openPhishInFlight } finally { openPhishInFlight = null }
}

async function checkOpenPhish(url: string): Promise<ThreatIntelProviderResult> {
  if (!env.OPENPHISH_ENABLED) return disabledResult('OpenPhish', 'Provider disabled by configuration.')
  try {
    const feed = await loadOpenPhishFeed()
    const matched = feed.has(comparableUrl(url))
    return {
      provider: 'OpenPhish',
      configured: true,
      status: matched ? 'MATCHED' : 'NO_MATCH',
      matched,
      checkedAt: checkedAt(),
      summary: matched ? 'The URL appears in the OpenPhish community feed.' : 'No exact URL match was found in the cached OpenPhish community feed.',
      details: { feedEntries: feed.size, cacheTtlMs: env.OPENPHISH_CACHE_TTL_MS },
    }
  } catch (error) {
    return errorResult('OpenPhish', error)
  }
}

async function checkGoogleWebRisk(url: string): Promise<ThreatIntelProviderResult> {
  if (!env.GOOGLE_WEB_RISK_API_KEY) return disabledResult('Google Web Risk', 'API key not configured.')
  try {
    const query = new URLSearchParams({ uri: url, key: env.GOOGLE_WEB_RISK_API_KEY })
    for (const type of env.GOOGLE_WEB_RISK_THREAT_TYPES.split(',').map((value) => value.trim()).filter(Boolean)) query.append('threatTypes', type)
    const response = await fetchWithTimeout(`${GOOGLE_WEB_RISK_URL}?${query.toString()}`, {
      headers: { 'User-Agent': env.APP_USER_AGENT },
      redirect: 'error',
    }, env.THREAT_PROVIDER_TIMEOUT_MS)
    if (!response.ok) return { ...errorResult('Google Web Risk', `HTTP ${response.status}`), status: response.status === 429 ? 'RATE_LIMITED' : 'UNAVAILABLE' }
    const payload = await readJsonWithLimit<any>(response, env.THREAT_PROVIDER_MAX_RESPONSE_BYTES, env.THREAT_PROVIDER_TIMEOUT_MS)
    const threatTypes = Array.isArray(payload?.threat?.threatTypes) ? payload.threat.threatTypes.map(String) : []
    const matched = threatTypes.length > 0
    return {
      provider: 'Google Web Risk',
      configured: true,
      status: matched ? 'MATCHED' : 'NO_MATCH',
      matched,
      checkedAt: checkedAt(),
      summary: matched ? `Google Web Risk matched: ${threatTypes.join(', ')}.` : 'No matching Web Risk threat list was returned.',
      threatTypes,
      details: { expireTime: payload?.expireTime ?? null },
    }
  } catch (error) {
    return errorResult('Google Web Risk', error)
  }
}

async function checkVirusTotal(url: string): Promise<ThreatIntelProviderResult> {
  if (!env.VIRUSTOTAL_ENABLED || !env.VIRUSTOTAL_API_KEY) return disabledResult('VirusTotal', env.VIRUSTOTAL_ENABLED ? 'API key not configured.' : 'Provider disabled by configuration.')
  try {
    const id = Buffer.from(url).toString('base64url')
    const response = await fetchWithTimeout(`${VIRUSTOTAL_URL}${id}`, {
      headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY, 'accept': 'application/json', 'User-Agent': env.APP_USER_AGENT },
      redirect: 'error',
    }, env.THREAT_PROVIDER_TIMEOUT_MS)
    if (response.status === 404) return { provider: 'VirusTotal', configured: true, status: 'NO_MATCH', matched: false, checkedAt: checkedAt(), summary: 'VirusTotal does not have a URL report for this identifier.' }
    if (!response.ok) return { ...errorResult('VirusTotal', `HTTP ${response.status}`), status: response.status === 429 ? 'RATE_LIMITED' : 'UNAVAILABLE' }
    const payload = await readJsonWithLimit<any>(response, env.THREAT_PROVIDER_MAX_RESPONSE_BYTES, env.THREAT_PROVIDER_TIMEOUT_MS)
    const stats = payload?.data?.attributes?.last_analysis_stats
    if (!stats || typeof stats !== 'object') throw new Error('VirusTotal returned an invalid URL report shape.')
    const malicious = Number(stats.malicious ?? 0)
    const suspicious = Number(stats.suspicious ?? 0)
    const matched = malicious > 0 || suspicious > 0
    return {
      provider: 'VirusTotal',
      configured: true,
      status: malicious > 0 ? 'MATCHED' : suspicious > 0 ? 'SUSPICIOUS' : 'NO_MATCH',
      matched,
      checkedAt: checkedAt(),
      summary: malicious > 0
        ? `${malicious} VirusTotal engines classified the URL as malicious.`
        : suspicious > 0
          ? `${suspicious} VirusTotal engines classified the URL as suspicious.`
          : 'VirusTotal returned no malicious or suspicious engine detections.',
      confidence: Number.isFinite(malicious + suspicious) ? Math.min(1, (malicious + suspicious) / Math.max(1, Object.values(stats).reduce((sum: number, value) => sum + Number(value || 0), 0))) : null,
      details: {
        malicious,
        suspicious,
        harmless: Number(stats.harmless ?? 0),
        undetected: Number(stats.undetected ?? 0),
      },
    }
  } catch (error) {
    return errorResult('VirusTotal', error)
  }
}

async function cachedProviderResult(key: string, loader: () => Promise<ThreatIntelProviderResult>): Promise<ThreatIntelProviderResult> {
  const now = Date.now()
  const cached = providerResultCache.get(key)
  if (cached && cached.expiresAt > now) return { ...cached.result, details: { ...(cached.result.details ?? {}), cached: true } }

  const inFlight = providerInFlight.get(key)
  if (inFlight) return { ...(await inFlight), details: { ...((await inFlight).details ?? {}), coalesced: true } }

  const request = loader()
  providerInFlight.set(key, request)
  try {
    const result = await request
    if (providerResultCache.size >= env.THREAT_RESULT_CACHE_MAX_ENTRIES) {
      const oldestKey = providerResultCache.keys().next().value
      if (oldestKey) providerResultCache.delete(oldestKey)
    }
    if (['MATCHED', 'NO_MATCH', 'SUSPICIOUS'].includes(result.status)) providerResultCache.set(key, { expiresAt: Date.now() + env.THREAT_RESULT_CACHE_TTL_MS, result })
    return result
  } finally {
    providerInFlight.delete(key)
  }
}

export type ThreatIntelLookupOptions = { blockExternalLookup?: boolean; blockReason?: string }

export async function collectThreatIntelligence(url: string, options: ThreatIntelLookupOptions = {}): Promise<ThreatIntelligenceAssessment> {
  const normalized = normalizeUrl(url)
  const blockReason = options.blockExternalLookup ? (options.blockReason ?? 'External threat-intelligence lookup was blocked by the safety policy.') : shouldBlockExternalLookup(normalized)
  const providers = blockReason
    ? [
        env.PHISHTANK_ENABLED ? blockedResult('PhishTank', blockReason) : disabledResult('PhishTank', 'Provider disabled by configuration.'),
        env.OPENPHISH_ENABLED ? blockedResult('OpenPhish', blockReason) : disabledResult('OpenPhish', 'Provider disabled by configuration.'),
        env.GOOGLE_WEB_RISK_API_KEY ? blockedResult('Google Web Risk', blockReason) : disabledResult('Google Web Risk', 'API key not configured.'),
        env.VIRUSTOTAL_ENABLED && env.VIRUSTOTAL_API_KEY ? blockedResult('VirusTotal', blockReason) : disabledResult('VirusTotal', env.VIRUSTOTAL_ENABLED ? 'API key not configured.' : 'Provider disabled by configuration.'),
      ]
    : await Promise.all([
        cachedProviderResult(`phishtank:${normalized}`, () => checkPhishTank(normalized)),
        cachedProviderResult(`openphish:${normalized}`, () => checkOpenPhish(normalized)),
        cachedProviderResult(`google-webrisk:${normalized}`, () => checkGoogleWebRisk(normalized)),
        cachedProviderResult(`virustotal:${normalized}`, () => checkVirusTotal(normalized)),
      ])

  const configuredProviders = providers.filter((item) => item.configured).length
  const availableProviders = providers.filter((item) => item.configured && ['MATCHED', 'NO_MATCH', 'SUSPICIOUS'].includes(item.status)).length
  const matchedSources = providers.filter((item) => item.status === 'MATCHED' && item.matched).map((item) => item.provider)
  const suspiciousSources = providers.filter((item) => item.status === 'SUSPICIOUS').map((item) => item.provider)
  const knownMalicious = matchedSources.length > 0
  const signalScore = knownMalicious ? 100 : suspiciousSources.length > 0 ? 70 : 0
  const configuredProviderResults = providers.filter((item) => item.configured)
  const blockedAll = configuredProviderResults.length > 0 && configuredProviderResults.every((item) => item.status === 'BLOCKED')
  const status = blockedAll ? 'BLOCKED' : configuredProviders === 0 || availableProviders === 0 ? 'UNAVAILABLE' : availableProviders < configuredProviders ? 'PARTIAL' : 'AVAILABLE'

  return {
    status,
    knownMalicious,
    matchedSources,
    suspiciousSources,
    signalScore,
    providers,
    availableProviders,
    configuredProviders,
    coveragePercent: configuredProviders === 0 ? 0 : Math.round((availableProviders / configuredProviders) * 100),
  }
}

export function clearThreatIntelCaches(): void {
  openPhishCache = null
  openPhishInFlight = null
  providerResultCache.clear()
  providerInFlight.clear()
}


export function getProviderConfiguration() {
  return [
    {
      name: 'PhishTank',
      configured: env.PHISHTANK_ENABLED,
      detail: !env.PHISHTANK_ENABLED
        ? 'Disabled by configuration'
        : env.PHISHTANK_APP_KEY && new URL(env.PHISHTANK_API_URL).protocol === 'https:'
          ? 'Enabled with application key'
          : env.PHISHTANK_APP_KEY
            ? 'Enabled; application key intentionally omitted from non-HTTPS endpoint'
            : 'Enabled without application key',
    },
    { name: 'OpenPhish', configured: env.OPENPHISH_ENABLED, detail: env.OPENPHISH_ENABLED ? 'Community feed adapter enabled' : 'Disabled by configuration' },
    { name: 'Google Web Risk', configured: Boolean(env.GOOGLE_WEB_RISK_API_KEY), detail: env.GOOGLE_WEB_RISK_API_KEY ? 'API key configured' : 'API key missing' },
    { name: 'VirusTotal', configured: env.VIRUSTOTAL_ENABLED && Boolean(env.VIRUSTOTAL_API_KEY), detail: !env.VIRUSTOTAL_ENABLED ? 'Opt-in provider disabled' : env.VIRUSTOTAL_API_KEY ? 'API key configured' : 'API key missing' },
    { name: 'RDAP', configured: true, detail: 'IANA bootstrap discovery' },
    { name: 'DNS', configured: true, detail: 'Node DNS resolver' },
    { name: 'TLS', configured: true, detail: 'Public-destination-gated certificate probe' },
  ]
}
