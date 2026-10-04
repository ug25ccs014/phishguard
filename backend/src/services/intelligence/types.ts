export type ProviderStatus = 'MATCHED' | 'NO_MATCH' | 'SUSPICIOUS' | 'UNAVAILABLE' | 'ERROR' | 'BLOCKED' | 'RATE_LIMITED'

export type ThreatIntelProviderResult = {
  provider: string
  configured: boolean
  status: ProviderStatus
  matched: boolean
  checkedAt: string
  summary: string
  threatTypes?: string[]
  firstSeen?: string | null
  lastSeen?: string | null
  confidence?: number | null
  details?: Record<string, string | number | boolean | null>
}

export type ThreatIntelligenceAssessment = {
  status: 'AVAILABLE' | 'PARTIAL' | 'UNAVAILABLE' | 'BLOCKED'
  knownMalicious: boolean
  matchedSources: string[]
  suspiciousSources: string[]
  signalScore: number
  providers: ThreatIntelProviderResult[]
  availableProviders: number
  configuredProviders: number
  coveragePercent: number
}

export type DNSIntelligence = {
  status: 'AVAILABLE' | 'PARTIAL' | 'UNAVAILABLE' | 'BLOCKED'
  ipv4: string[]
  ipv6: string[]
  mx: string[]
  ns: string[]
  privateAddresses: string[]
  publicAddresses: string[]
  noAddressRecord: boolean
  score: number
  reasons: string[]
}

export type TLSIntelligence = {
  status: 'AVAILABLE' | 'NOT_APPLICABLE' | 'UNAVAILABLE' | 'BLOCKED'
  authorized: boolean | null
  authorizationError: string | null
  subject: string | null
  issuer: string | null
  validFrom: string | null
  validTo: string | null
  daysRemaining: number | null
  score: number
  reasons: string[]
}

export type RDAPIntelligence = {
  status: 'AVAILABLE' | 'NOT_FOUND' | 'UNAVAILABLE' | 'NOT_APPLICABLE'
  rdapServer: string | null
  registrableDomain: string | null
  registrar: string | null
  statuses: string[]
  nameservers: string[]
  createdAt: string | null
  updatedAt: string | null
  expiresAt: string | null
  daysOld: number | null
  score: number
  reasons: string[]
}

export type DomainIntelligenceAssessment = {
  status: 'AVAILABLE' | 'PARTIAL' | 'UNAVAILABLE' | 'BLOCKED'
  hostname: string
  rdap: RDAPIntelligence
  dns: DNSIntelligence
  tls: TLSIntelligence
  signalScore: number
  reasons: string[]
}

export type RiskSignal = {
  name: string
  score: number
  weight: number
  included: boolean
  rationale: string
}

export type RiskAssessment = {
  verdict: 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK' | 'LIKELY PHISHING' | 'KNOWN MALICIOUS'
  riskScore: number
  signals: RiskSignal[]
  reasons: string[]
  recommendation: string
  methodology: string
}
