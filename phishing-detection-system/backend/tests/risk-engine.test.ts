import { describe, expect, it } from 'vitest'
import { calculateRisk, scoreHeuristics } from '../src/services/intelligence/riskEngine.js'
import type { DomainIntelligenceAssessment, ThreatIntelligenceAssessment } from '../src/services/intelligence/types.js'
import type { MLResponse } from '../src/services/mlClient.js'

const cleanFeatures: MLResponse['features'] = {
  url_length: 24, hostname_length: 11, path_length: 1, query_length: 0, fragment_length: 0,
  dot_count: 1, slash_count: 2, hyphen_count: 0, underscore_count: 0, digit_count: 0,
  special_char_count: 0, at_symbol: 0, has_ip_hostname: 0, has_punycode: 0, double_slash_redirect: 0,
  subdomain_count: 0, path_depth: 0, percent_encoded_count: 0, suspicious_term_count: 0, entropy: 3.2,
  uses_shortener: 0, https: 1, hostname_has_digit: 0, hostname_has_hyphen: 0, path_has_extension: 0,
  query_parameter_count: 0, hostname_letter_ratio: 0.9,
}

const baseThreat: ThreatIntelligenceAssessment = {
  status: 'AVAILABLE', knownMalicious: false, matchedSources: [], suspiciousSources: [], signalScore: 0,
  providers: [{ provider: 'Test', configured: true, status: 'NO_MATCH', matched: false, checkedAt: new Date().toISOString(), summary: 'No match' }],
  availableProviders: 1, configuredProviders: 1, coveragePercent: 100,
}

const baseDomain: DomainIntelligenceAssessment = {
  status: 'AVAILABLE', hostname: 'example.com', signalScore: 0, reasons: [],
  rdap: { status: 'AVAILABLE', rdapServer: 'https://example.test/', registrableDomain: 'example.com', registrar: 'Example', statuses: [], nameservers: [], createdAt: new Date(Date.now() - 365 * 86400000).toISOString(), updatedAt: null, expiresAt: null, daysOld: 365, score: 0, reasons: [] },
  dns: { status: 'AVAILABLE', ipv4: ['93.184.216.34'], ipv6: [], mx: [], ns: [], privateAddresses: [], publicAddresses: ['93.184.216.34'], noAddressRecord: false, score: 0, reasons: [] },
  tls: { status: 'AVAILABLE', authorized: true, authorizationError: null, subject: 'example.com', issuer: 'CA', validFrom: null, validTo: null, daysRemaining: 100, score: 0, reasons: [] },
}

const ml = (p: number) => ({
  prediction: p >= 0.5 ? 1 : 0, label: p >= 0.5 ? 'PHISHING' : 'LEGITIMATE', phishingProbability: p,
  legitimateProbability: 1 - p, featureVersion: 'url-lexical-v1', modelVersion: 'test', modelName: 'test',
  features: cleanFeatures, topModelFeatures: [],
} as MLResponse)

describe('Step 3 risk engine', () => {
  it('excludes unavailable threat intelligence from weighted scoring', () => {
    const unavailable = { ...baseThreat, status: 'UNAVAILABLE' as const, availableProviders: 0, configuredProviders: 1, coveragePercent: 0, providers: [{ ...baseThreat.providers[0], status: 'ERROR' as const }] }
    const result = calculateRisk(0.2, scoreHeuristics(cleanFeatures), unavailable, baseDomain)
    expect(result.riskScore).toBeLessThan(30)
    expect(result.signals.find((signal) => signal.name === 'Threat intelligence')?.included).toBe(false)
  })

  it('uses a known threat match as an explicit override', () => {
    const matched = { ...baseThreat, knownMalicious: true, matchedSources: ['PhishTank'], signalScore: 100, providers: [{ ...baseThreat.providers[0], status: 'MATCHED' as const, matched: true }] }
    const result = calculateRisk(0.1, scoreHeuristics(cleanFeatures), matched, baseDomain)
    expect(result.verdict).toBe('KNOWN MALICIOUS')
    expect(result.riskScore).toBe(100)
    expect(result.reasons[0]).toContain('PhishTank')
  })
})
