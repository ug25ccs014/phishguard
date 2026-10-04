import type { MLResponse } from '../mlClient.js'
import type { DomainIntelligenceAssessment, RiskAssessment, RiskSignal, ThreatIntelligenceAssessment } from './types.js'

export type HeuristicAssessment = { score: number; level: string; reasons: string[] }

export function scoreHeuristics(features: MLResponse['features']): HeuristicAssessment {
  let score = 0
  const reasons: string[] = []
  const add = (points: number, reason: string) => { score += points; reasons.push(reason) }

  if (features.has_ip_hostname === 1) add(30, 'The hostname is an IP address rather than a conventional domain name.')
  if (features.at_symbol === 1) add(20, 'The URL contains an @ symbol, a known deceptive URL pattern.')
  if (features.has_punycode === 1) add(15, 'The hostname contains Punycode/IDN encoding that requires closer review.')
  if (features.double_slash_redirect === 1) add(10, 'The URL contains a double-slash redirect pattern outside the authority component.')
  if (features.uses_shortener === 1) add(10, 'The URL uses a shortening service that obscures the final destination.')
  if (features.subdomain_count >= 3) add(10, 'The URL contains a deep subdomain structure.')
  if (features.suspicious_term_count >= 2) add(15, 'Multiple credential, account, payment, security, or verification terms appear in the URL.')
  if (features.url_length >= 120) add(10, 'The URL is unusually long.')
  if (features.percent_encoded_count >= 4) add(10, 'The URL contains a high amount of percent-encoded data.')

  const capped = Math.min(100, score)
  return { score: capped, level: capped >= 70 ? 'HIGH' : capped >= 30 ? 'ELEVATED' : 'NORMAL', reasons: reasons.slice(0, 8) }
}

function verdictFor(score: number): RiskAssessment['verdict'] {
  if (score >= 80) return 'LIKELY PHISHING'
  if (score >= 60) return 'HIGH RISK'
  if (score >= 30) return 'SUSPICIOUS'
  return 'LOW RISK'
}

function recommendationFor(verdict: RiskAssessment['verdict']): string {
  if (verdict === 'KNOWN MALICIOUS' || verdict === 'LIKELY PHISHING' || verdict === 'HIGH RISK') return 'Do not open the destination or enter passwords, OTPs, payment details, or other sensitive information. Verify the organization through a trusted channel.'
  if (verdict === 'SUSPICIOUS') return 'Treat the URL cautiously. Verify the domain independently before proceeding or entering sensitive information.'
  return 'No major threat signal was identified by the currently available checks. This is not a guarantee of safety; independently verify important destinations.'
}

export function calculateRisk(mlProbability: number, heuristic: HeuristicAssessment, threat: ThreatIntelligenceAssessment, domain: DomainIntelligenceAssessment): RiskAssessment {
  const signals: RiskSignal[] = []
  const mlScore = Math.round(mlProbability * 100)
  signals.push({ name: 'Machine learning', score: mlScore, weight: 0.50, included: true, rationale: 'Versioned URL-classification model probability.' })
  signals.push({ name: 'URL heuristics', score: heuristic.score, weight: 0.20, included: true, rationale: 'Deterministic structural and lexical red-flag rules.' })
  const threatIncluded = threat.availableProviders > 0
  signals.push({ name: 'Threat intelligence', score: threat.signalScore, weight: 0.20, included: threatIncluded, rationale: `${threat.availableProviders}/${threat.providers.length} intelligence providers returned usable responses.` })
  const domainIncluded = domain.status !== 'UNAVAILABLE'
  signals.push({ name: 'Domain intelligence', score: domain.rdap.score, weight: 0.05, included: domainIncluded && domain.rdap.status === 'AVAILABLE', rationale: 'RDAP registration age and lifecycle signals.' })
  const dnsTlsScores: number[] = []
  if (domain.dns.status !== 'UNAVAILABLE') dnsTlsScores.push(domain.dns.score)
  if (domain.tls.status === 'AVAILABLE' || domain.tls.status === 'BLOCKED') dnsTlsScores.push(domain.tls.score)
  const dnsTlsScore = dnsTlsScores.length ? Math.min(100, Math.round(dnsTlsScores.reduce((sum, value) => sum + value, 0) / dnsTlsScores.length)) : 0
  const dnsTlsIncluded = dnsTlsScores.length > 0
  signals.push({ name: 'DNS/TLS', score: dnsTlsScore, weight: 0.05, included: dnsTlsIncluded, rationale: 'DNS resolution and TLS certificate observations.' })

  if (threat.knownMalicious) {
    const reasons = [
      `Threat intelligence matched: ${threat.matchedSources.join(', ')}.`,
      ...heuristic.reasons,
      ...domain.reasons,
    ].filter((value, index, array) => array.indexOf(value) === index).slice(0, 8)
    return {
      verdict: 'KNOWN MALICIOUS', riskScore: 100, signals, reasons,
      recommendation: recommendationFor('KNOWN MALICIOUS'),
      methodology: 'A verified/known malicious threat-intelligence match overrides the weighted risk score. Other signals remain visible for context.',
    }
  }

  const included = signals.filter((signal) => signal.included)
  const weightTotal = included.reduce((sum, signal) => sum + signal.weight, 0)
  const riskScore = Math.max(0, Math.min(100, Math.round(included.reduce((sum, signal) => sum + signal.score * signal.weight, 0) / Math.max(weightTotal, 0.0001))))
  const verdict = verdictFor(riskScore)
  const reasons = [
    mlProbability >= 0.5 ? `The machine-learning classifier estimates a ${(mlProbability * 100).toFixed(1)}% phishing probability.` : `The machine-learning classifier estimates a ${((1 - mlProbability) * 100).toFixed(1)}% legitimate probability.`,
    ...heuristic.reasons,
    ...(threat.suspiciousSources.length ? [`Suspicious provider signal from: ${threat.suspiciousSources.join(', ')}.`] : []),
    ...domain.reasons,
  ].filter((value, index, array) => array.indexOf(value) === index).slice(0, 8)
  if (reasons.length === 1) reasons.push('No additional high-confidence external indicator was returned by the currently available enrichment providers.')
  return {
    verdict,
    riskScore,
    signals,
    reasons,
    recommendation: recommendationFor(verdict),
    methodology: 'Weighted, coverage-aware combination of ML, deterministic URL heuristics, threat intelligence, RDAP, and DNS/TLS signals. Unavailable providers are excluded rather than treated as clean.',
  }
}
