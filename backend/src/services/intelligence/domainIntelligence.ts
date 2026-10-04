import dns from 'node:dns'
import net from 'node:net'
import tls from 'node:tls'
import { env } from '../../config/env.js'
import { fetchWithTimeout, readJsonWithLimit } from './http.js'
import { getDomain } from 'tldts'
import type { DNSIntelligence, DomainIntelligenceAssessment, RDAPIntelligence, TLSIntelligence } from './types.js'

const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'
const resolver = dns.promises
let rdapBootstrapCache: { fetchedAt: number; services: Array<{ tlds: string[]; servers: string[] }> } | null = null

function timeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Operation timed out.')), ms)
    promise.then((value) => { clearTimeout(timer); resolve(value) }, (error) => { clearTimeout(timer); reject(error) })
  })
}

function isPrivateOrReservedAddress(value: string): boolean {
  const kind = net.isIP(value)
  if (kind === 4) {
    const [a, b, c] = value.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 0 || b === 168)) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0 && c === 113) || a >= 224
  }
  if (kind === 6) {
    const lower = value.toLowerCase()
    const mapped = lower.startsWith('::ffff:') ? lower.slice(7) : null
    if (mapped && net.isIP(mapped) === 4) return isPrivateOrReservedAddress(mapped)
    const first = Number.parseInt(lower.split(':')[0] || '0', 16)
    const second = Number.parseInt(lower.split(':')[1] || '0', 16)
    return lower === '::' || lower === '::1' || first === 0 || (first >= 0xfc00 && first <= 0xfdff) || (first >= 0xfe80 && first <= 0xfebf) || first >= 0xff00 || (first === 0x2001 && second === 0x0db8)
  }
  return true
}

function registrableDomain(hostname: string): string {
  if (net.isIP(hostname)) return hostname
  return getDomain(hostname, { allowPrivateDomains: false }) ?? hostname.toLowerCase().replace(/\.$/, '')
}

async function loadRdapBootstrap(): Promise<Array<{ tlds: string[]; servers: string[] }>> {
  const now = Date.now()
  if (rdapBootstrapCache && now - rdapBootstrapCache.fetchedAt < env.RDAP_BOOTSTRAP_CACHE_TTL_MS) return rdapBootstrapCache.services
  const response = await fetchWithTimeout(RDAP_BOOTSTRAP_URL, { headers: { 'User-Agent': env.APP_USER_AGENT }, redirect: 'error' }, env.RDAP_TIMEOUT_MS)
  if (!response.ok) throw new Error(`RDAP bootstrap HTTP ${response.status}`)
  const payload = await readJsonWithLimit<any>(response, env.RDAP_MAX_RESPONSE_BYTES, env.RDAP_TIMEOUT_MS)
  const services = Array.isArray(payload?.services)
    ? payload.services.map((entry: any[]) => ({ tlds: Array.isArray(entry?.[0]) ? entry[0].map(String).filter(Boolean) : [], servers: Array.isArray(entry?.[1]) ? entry[1].map(String).filter(Boolean) : [] })).filter((entry: any) => entry.tlds.length && entry.servers.length)
    : []
  if (services.length === 0) throw new Error('RDAP bootstrap returned an invalid or empty service registry.')
  rdapBootstrapCache = { fetchedAt: now, services }
  return services
}

async function lookupRDAP(hostname: string): Promise<RDAPIntelligence> {
  const fallback: RDAPIntelligence = {
    status: 'UNAVAILABLE', rdapServer: null, registrableDomain: null, registrar: null, statuses: [], nameservers: [], createdAt: null, updatedAt: null, expiresAt: null, daysOld: null, score: 0, reasons: [],
  }
  if (net.isIP(hostname)) return { ...fallback, status: 'NOT_APPLICABLE' }
  const cleanedHostname = hostname.replace(/\.$/, '')
  if (/(^|\.)localhost$|(^|\.)local$|(^|\.)internal$|(^|\.)test$|(^|\.)invalid$|(^|\.)example$|(^|\.)home\.arpa$/i.test(cleanedHostname)) {
    return { ...fallback, status: 'NOT_APPLICABLE', registrableDomain: registrableDomain(cleanedHostname), reasons: ['RDAP lookup is not attempted for local or special-use hostnames.'] }
  }
  const domain = registrableDomain(cleanedHostname)
  const tld = domain.split('.').pop() ?? ''
  try {
    const services = await loadRdapBootstrap()
    const service = services.find((entry) => entry.tlds.some((value) => value.toLowerCase() === tld.toLowerCase()))
    if (!service) return { ...fallback, status: 'NOT_FOUND', registrableDomain: domain, reasons: ['No RDAP bootstrap service was found for this top-level domain.'] }

    const bases = service.servers.filter((value) => {
      try { return new URL(value).protocol === 'https:' } catch { return false }
    }).slice(0, 3)
    if (!bases.length) return { ...fallback, status: 'UNAVAILABLE', registrableDomain: domain, reasons: ['The RDAP bootstrap service did not advertise an HTTPS endpoint.'] }

    let lastFailure = 'RDAP lookup failed.'
    let sawNotFound = false
    for (const base of bases) {
      try {
        const endpoint = new URL(`domain/${encodeURIComponent(domain)}`, base.endsWith('/') ? base : `${base}/`)
        const response = await fetchWithTimeout(endpoint, { redirect: 'error', headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': env.APP_USER_AGENT } }, env.RDAP_TIMEOUT_MS)
        if (response.status === 404) { sawNotFound = true; continue }
        if (!response.ok) { lastFailure = `RDAP service returned HTTP ${response.status}.`; continue }
        const payload = await readJsonWithLimit<any>(response, env.RDAP_MAX_RESPONSE_BYTES, env.RDAP_TIMEOUT_MS)
        const events = Array.isArray(payload?.events) ? payload.events : []
        const event = (action: string) => events.find((item: any) => String(item?.eventAction).toLowerCase() === action)?.eventDate ?? null
        const registrarEntity = Array.isArray(payload?.entities) ? payload.entities.find((entity: any) => Array.isArray(entity?.roles) && entity.roles.map(String).includes('registrar')) : null
        const registrar = extractVcardText(registrarEntity?.vcardArray) || registrarEntity?.handle || null
        const nameservers = Array.isArray(payload?.nameservers)
          ? payload.nameservers.map((ns: any) => ns?.ldhName || ns?.unicodeName).filter(Boolean).map(String).slice(0, 8)
          : []
        const rawCreatedAt = event('registration')
        const rawUpdatedAt = event('last changed')
        const rawExpiresAt = event('expiration')
        const createdAt = rawCreatedAt && Number.isFinite(new Date(rawCreatedAt).getTime()) ? rawCreatedAt : null
        const updatedAt = rawUpdatedAt && Number.isFinite(new Date(rawUpdatedAt).getTime()) ? rawUpdatedAt : null
        const expiresAt = rawExpiresAt && Number.isFinite(new Date(rawExpiresAt).getTime()) ? rawExpiresAt : null
        const daysOld = createdAt ? Math.max(0, Math.floor((Date.now() - new Date(createdAt).getTime()) / 86_400_000)) : null
        let score = 0
        const reasons: string[] = []
        if (daysOld !== null) {
          if (daysOld < 7) { score += 65; reasons.push('The domain was registered less than 7 days ago.') }
          else if (daysOld < 30) { score += 45; reasons.push('The domain was registered less than 30 days ago.') }
          else if (daysOld < 180) { score += 25; reasons.push('The domain is relatively young (under 180 days).') }
        }
        const statuses = Array.isArray(payload?.status) ? payload.status.map(String) : []
        if (statuses.some((value: string) => /pendingDelete|redemptionPeriod|inactive/i.test(value))) {
          score += 20
          reasons.push('The RDAP record contains a lifecycle status that warrants additional review.')
        }
        return {
          status: 'AVAILABLE', rdapServer: base, registrableDomain: domain, registrar, statuses, nameservers,
          createdAt, updatedAt, expiresAt, daysOld, score: Math.min(100, score), reasons,
        }
      } catch (error) {
        lastFailure = error instanceof Error ? error.message.slice(0, 200) : 'RDAP lookup failed.'
      }
    }
    if (sawNotFound && lastFailure === 'RDAP lookup failed.') return { ...fallback, status: 'NOT_FOUND', registrableDomain: domain, reasons: ['The RDAP service did not return a record for this domain.'] }
    return { ...fallback, status: 'UNAVAILABLE', registrableDomain: domain, reasons: [lastFailure] }
  } catch (error) {
    return { ...fallback, registrableDomain: domain, reasons: [error instanceof Error ? error.message.slice(0, 200) : 'RDAP lookup failed.'] }
  }
}
function extractVcardText(vcardArray: unknown): string | null {
  if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return null
  for (const entry of vcardArray[1]) {
    if (!Array.isArray(entry) || entry.length < 4) continue
    if (entry[0] === 'fn' || entry[0] === 'org') {
      const value = Array.isArray(entry[3]) ? entry[3].join(' ') : entry[3]
      if (typeof value === 'string' && value.trim()) return value.trim()
    }
  }
  return null
}

async function resolveRecord<T>(operation: Promise<T>): Promise<T | null> {
  try { return await timeout(operation, env.DNS_TIMEOUT_MS) } catch { return null }
}

async function collectDNS(hostname: string): Promise<DNSIntelligence> {
  const base: DNSIntelligence = { status: 'UNAVAILABLE', ipv4: [], ipv6: [], mx: [], ns: [], privateAddresses: [], publicAddresses: [], noAddressRecord: false, score: 0, reasons: [] }
  const lower = hostname.toLowerCase().replace(/\.$/, '')
  if (!net.isIP(hostname) && /(^|\.)localhost$|(^|\.)local$|(^|\.)internal$|(^|\.)test$|(^|\.)invalid$|(^|\.)example$|(^|\.)home\.arpa$/i.test(lower)) {
    return { ...base, status: 'BLOCKED', score: 70, reasons: ['DNS enrichment is blocked for local or special-use hostnames.'] }
  }
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedAddress(hostname)) return { ...base, status: 'BLOCKED', privateAddresses: [hostname], score: 80, reasons: ['The submitted hostname is a private or reserved IP address; network enrichment is blocked.'] }
    return { ...base, status: 'AVAILABLE', publicAddresses: [hostname], noAddressRecord: false, score: 0, reasons: [] }
  }

  const [ipv4, ipv6, mx, ns] = await Promise.all([
    resolveRecord(resolver.resolve4(hostname)),
    resolveRecord(resolver.resolve6(hostname)),
    resolveRecord(resolver.resolveMx(hostname)),
    resolveRecord(resolver.resolveNs(hostname)),
  ])
  const addresses = [...(ipv4 ?? []), ...(ipv6 ?? [])]
  const privateAddresses = addresses.filter(isPrivateOrReservedAddress)
  const publicAddresses = addresses.filter((value) => !isPrivateOrReservedAddress(value))
  const reasons: string[] = []
  let score = 0
  if (addresses.length === 0) {
    score += 30
    reasons.push('No public A/AAAA address record was resolved for the hostname.')
  }
  if (privateAddresses.length > 0) {
    score += 80
    reasons.push('DNS resolution returned a private or reserved address; active network enrichment is blocked for this destination.')
  }
  if ((mx ?? []).length === 0) reasons.push('No MX record was observed; this is contextual information, not proof of maliciousness.')
  return {
    status: privateAddresses.length > 0 ? 'BLOCKED' : addresses.length || (mx ?? []).length || (ns ?? []).length ? 'AVAILABLE' : 'PARTIAL',
    ipv4: ipv4 ?? [], ipv6: ipv6 ?? [], mx: (mx ?? []).map((item: any) => String(item.exchange)).slice(0, 8), ns: (ns ?? []).map(String).slice(0, 8),
    privateAddresses, publicAddresses, noAddressRecord: addresses.length === 0, score: Math.min(100, score), reasons,
  }
}

async function probeTLS(hostname: string, publicIp: string): Promise<TLSIntelligence> {
  return await new Promise<TLSIntelligence>((resolve) => {
    const socket = tls.connect({ host: publicIp, port: 443, servername: hostname, rejectUnauthorized: false, minVersion: 'TLSv1.2' })
    let settled = false
    const finish = (result: TLSIntelligence) => { if (settled) return; settled = true; clearTimeout(timer); socket.end(); socket.destroy(); resolve(result) }
    const timer = setTimeout(() => finish({ status: 'UNAVAILABLE', authorized: null, authorizationError: 'TLS handshake timed out.', subject: null, issuer: null, validFrom: null, validTo: null, daysRemaining: null, score: 15, reasons: ['The TLS handshake timed out.'] }), env.TLS_TIMEOUT_MS)
    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate()
      const hostnameError = certificate && typeof certificate === 'object' && Object.keys(certificate).length > 0 ? tls.checkServerIdentity(hostname, certificate) : new Error('No peer certificate was presented.')
      const authorized = socket.authorized && !hostnameError
      const validToMs = certificate?.valid_to ? new Date(certificate.valid_to).getTime() : NaN
      const daysRemaining = Number.isFinite(validToMs) ? Math.floor((validToMs - Date.now()) / 86_400_000) : null
      const reasons: string[] = []
      let score = 0
      if (!authorized) {
        score += 55
        reasons.push(`TLS certificate validation failed: ${socket.authorizationError ?? hostnameError?.message ?? 'unknown error'}.`)
      }
      if (hostnameError) {
        score += 35
        reasons.push(`TLS certificate hostname validation failed: ${hostnameError.message.slice(0, 180)}.`)
      }
      if (daysRemaining !== null && daysRemaining < 0) { score += 80; reasons.push('The presented TLS certificate is expired.') }
      else if (daysRemaining !== null && daysRemaining < 14) { score += 20; reasons.push('The TLS certificate expires within 14 days.') }
      finish({
        status: 'AVAILABLE', authorized, authorizationError: socket.authorizationError ?? hostnameError?.message ?? null,
        subject: certificate?.subject?.CN ?? null, issuer: certificate?.issuer?.CN ?? null,
        validFrom: certificate?.valid_from ?? null, validTo: certificate?.valid_to ?? null,
        daysRemaining, score: Math.min(100, score), reasons,
      })
    })
    socket.once('error', (error) => finish({ status: 'UNAVAILABLE', authorized: null, authorizationError: error instanceof Error ? error.message.slice(0, 160) : 'TLS connection failed.', subject: null, issuer: null, validFrom: null, validTo: null, daysRemaining: null, score: 10, reasons: ['A TLS certificate could not be retrieved from the resolved public address.'] }))
  })
}

export async function collectDomainIntelligence(hostname: string, protocol: string): Promise<DomainIntelligenceAssessment> {
  if (net.isIP(hostname) && isPrivateOrReservedAddress(hostname)) {
    const blockedDns = await collectDNS(hostname)
    return {
      status: 'BLOCKED', hostname, rdap: { status: 'NOT_APPLICABLE', rdapServer: null, registrableDomain: null, registrar: null, statuses: [], nameservers: [], createdAt: null, updatedAt: null, expiresAt: null, daysOld: null, score: 0, reasons: [] },
      dns: blockedDns,
      tls: { status: 'BLOCKED', authorized: null, authorizationError: null, subject: null, issuer: null, validFrom: null, validTo: null, daysRemaining: null, score: 0, reasons: ['TLS probing is blocked for private/reserved destinations.'] },
      signalScore: blockedDns.score, reasons: blockedDns.reasons,
    }
  }

  const rdapPromise = lookupRDAP(hostname)
  const dnsPromise = collectDNS(hostname)
  const [rdap, dns] = await Promise.all([rdapPromise, dnsPromise])
  let tlsResult: TLSIntelligence = { status: protocol === 'https:' ? 'UNAVAILABLE' : 'NOT_APPLICABLE', authorized: null, authorizationError: null, subject: null, issuer: null, validFrom: null, validTo: null, daysRemaining: null, score: 0, reasons: [] }
  if (protocol === 'https:' && dns.privateAddresses.length === 0 && dns.publicAddresses.length > 0) tlsResult = await probeTLS(hostname, dns.publicAddresses[0])
  else if (protocol === 'https:' && dns.privateAddresses.length > 0) tlsResult = { status: 'BLOCKED', authorized: null, authorizationError: null, subject: null, issuer: null, validFrom: null, validTo: null, daysRemaining: null, score: 40, reasons: ['TLS probing was blocked because DNS resolution included a private or reserved destination.'] }

  const reasons = [...rdap.reasons, ...dns.reasons, ...tlsResult.reasons]
  const scores = [rdap.score, dns.score, tlsResult.score].filter((value, index) => index === 0 ? rdap.status === 'AVAILABLE' : index === 1 ? dns.status !== 'UNAVAILABLE' : tlsResult.status === 'AVAILABLE')
  const signalScore = scores.length ? Math.min(100, Math.round(scores.reduce((sum, value) => sum + value, 0) / scores.length)) : 0
  const statuses = [rdap.status, dns.status, tlsResult.status]
  const status = statuses.some((value) => value === 'BLOCKED') ? 'BLOCKED' : statuses.every((value) => ['UNAVAILABLE', 'NOT_FOUND'].includes(value)) ? 'UNAVAILABLE' : statuses.some((value) => value === 'UNAVAILABLE' || value === 'PARTIAL' || value === 'NOT_FOUND') ? 'PARTIAL' : 'AVAILABLE'
  return { status, hostname, rdap, dns, tls: tlsResult, signalScore, reasons }
}

export function clearDomainCaches(): void { rdapBootstrapCache = null }
