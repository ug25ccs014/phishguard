import { describe, expect, it } from 'vitest'

function provisionalVerdict(score: number) {
  if (score >= 80) return 'LIKELY PHISHING'
  if (score >= 60) return 'HIGH RISK'
  if (score >= 30) return 'SUSPICIOUS'
  return 'LOW RISK'
}

describe('Step 2 ML integration contract', () => {
  it('maps the ML probability to the documented provisional bands', () => {
    expect(provisionalVerdict(0)).toBe('LOW RISK')
    expect(provisionalVerdict(29)).toBe('LOW RISK')
    expect(provisionalVerdict(30)).toBe('SUSPICIOUS')
    expect(provisionalVerdict(59)).toBe('SUSPICIOUS')
    expect(provisionalVerdict(60)).toBe('HIGH RISK')
    expect(provisionalVerdict(79)).toBe('HIGH RISK')
    expect(provisionalVerdict(80)).toBe('LIKELY PHISHING')
  })
})
