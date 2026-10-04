import type { RiskLevel } from '../types'
import { Badge } from './ui/Badge'

export function RiskBadge({ verdict }: { verdict: RiskLevel }) {
  const tone = verdict === 'LOW RISK' ? 'green' : verdict === 'SUSPICIOUS' ? 'yellow' : verdict === 'KNOWN MALICIOUS' ? 'red' : 'red'
  return <Badge tone={tone}>{verdict}</Badge>
}
