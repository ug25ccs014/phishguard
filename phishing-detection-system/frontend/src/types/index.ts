export type RiskLevel = 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK' | 'LIKELY PHISHING' | 'KNOWN MALICIOUS'

export type ThreatProviderResult = {
  provider: string
  configured: boolean
  status: 'MATCHED' | 'NO_MATCH' | 'SUSPICIOUS' | 'UNAVAILABLE' | 'ERROR' | 'BLOCKED' | 'RATE_LIMITED'
  matched: boolean
  checkedAt: string
  summary: string
  threatTypes?: string[]
  firstSeen?: string | null
  lastSeen?: string | null
  confidence?: number | null
  details?: Record<string, string | number | boolean | null>
}

export type ScanResult = {
  id: string
  url: string
  normalizedUrl: string
  domain: string
  verdict: RiskLevel
  riskScore: number
  scannedAt: string
  modelVersion: string
  signals: {
    ml: string
    heuristics: string
    threatIntelligence: string
    domain: string
    dnsTls: string
  }
  reasons: string[]
  recommendation: string
  methodology: string
  ml: {
    prediction: 0 | 1
    label: 'LEGITIMATE' | 'PHISHING'
    phishingProbability: number
    legitimateProbability: number
    featureVersion: string
    modelVersion: string
    modelName: string
    features: Record<string, number>
    topModelFeatures: Array<{ feature: string; importance: number }>
    probabilityCalibrated: boolean
  }
  threatIntelligence: {
    status: 'AVAILABLE' | 'PARTIAL' | 'UNAVAILABLE' | 'BLOCKED'
    knownMalicious: boolean
    matchedSources: string[]
    suspiciousSources: string[]
    signalScore: number
    providers: ThreatProviderResult[]
    availableProviders: number
    configuredProviders: number
    coveragePercent: number
  }
  domainIntelligence: {
    status: 'AVAILABLE' | 'PARTIAL' | 'UNAVAILABLE' | 'BLOCKED'
    hostname: string
    rdap: {
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
    dns: {
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
    tls: {
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
    signalScore: number
    reasons: string[]
  }
  riskBreakdown: Array<{
    name: string
    score: number
    weight: number
    included: boolean
    rationale: string
  }>
  persistence: 'PERSISTED' | 'NOT_PERSISTED'
}

export type ScanHistoryItem = {
  id: string
  url: string
  verdict: RiskLevel
  riskScore: number
  scannedAt: string
}


export type AuthUser = {
  id: string
  email: string
  name: string
  role: 'USER' | 'ADMIN'
  highRiskAlerts: boolean
  weeklySummary: boolean
}

export type DashboardResponse = {
  stats: { total: number; lowRisk: number; suspicious: number; highRisk: number }
  trend: Array<{ date: string; scans: number }>
  recent: ScanHistoryItem[]
}

export type ScanHistoryResponse = {
  items: Array<ScanHistoryItem & { domain: string; modelVersion: string | null }>
  pagination: { page: number; pageSize: number; total: number; totalPages: number }
}

export type PhishingReport = {
  id: string
  url: string
  category: string
  description: string | null
  status: 'PENDING' | 'REVIEWED' | 'CONFIRMED' | 'REJECTED'
  createdAt: string
  updatedAt?: string
  reviewedAt?: string | null
  reviewNote?: string | null
  user?: { id: string; name: string; email: string } | null
}

export type AdminOverviewResponse = {
  stats: { users: number; scans: number; lowRisk: number; suspicious: number; highRisk: number; openReports: number }
  trend: Array<{ date: string; phishing: number; suspicious: number }>
  recentReports: Array<Pick<PhishingReport, 'id' | 'url' | 'category' | 'status' | 'createdAt'>>
}

export type AdminProvider = { name: string; configured: boolean; detail: string }

export type AdminModelResponse = {
  model: {
    model_version?: string
    feature_version?: string
    selected_model?: string
    label_definition?: Record<string, string>
    dataset?: Record<string, unknown>
    test_metrics?: Record<string, unknown>
    validation_model_comparison?: Array<Record<string, unknown>>
    source_note?: string
    feature_names?: string[]
  }
}
