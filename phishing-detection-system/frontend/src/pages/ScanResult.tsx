import { AlertTriangle, ArrowLeft, CheckCircle2, Clock3, Database, Globe2, Info, LockKeyhole, Radar, Server, ShieldAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { useEffect, useState } from 'react'
import type { ScanResult as ScanResultType } from '../types'
import { RiskBadge } from '../components/RiskBadge'
import { SignalCard } from '../components/SignalCard'
import { ButtonLink } from '../components/ui/Button'
import { apiErrorMessage, getStoredScan } from '../services/api'

export function ScanResult() {
  const location = useLocation()
  const { id } = useParams()
  const stateResult = (location.state as { result?: ScanResultType } | null)?.result
  const [loadedResult, setLoadedResult] = useState<ScanResultType | null>(stateResult ?? null)
  const [loading, setLoading] = useState(!stateResult && Boolean(id))
  const [error, setError] = useState('')

  useEffect(() => {
    if (stateResult || !id) return
    setLoading(true)
    void getStoredScan(id).then(setLoadedResult).catch((e) => setError(apiErrorMessage(e, 'Could not load this saved scan.'))).finally(() => setLoading(false))
  }, [id, stateResult])

  if (loading) return <div className="mx-auto grid min-h-[50vh] place-items-center text-sm text-slate-500">Loading saved scan…</div>
  if (error) return <div className="mx-auto max-w-3xl"><div className="panel p-8 text-center"><Info className="mx-auto text-rose-300" size={28}/><h1 className="mt-4 text-xl font-semibold text-white">Scan unavailable</h1><p className="mt-2 text-sm text-slate-500">{error}</p><ButtonLink to="/history" className="mt-6">Back to history</ButtonLink></div></div>
  const result = loadedResult
  if (!result) {
    return <div className="mx-auto max-w-3xl"><div className="panel p-8 text-center"><Info className="mx-auto text-sky-300" size={28}/><h1 className="mt-4 text-xl font-semibold text-white">No scan result loaded</h1><p className="mt-2 text-sm text-slate-500">Start a new URL scan to generate a live security assessment.</p><ButtonLink to="/scanner" className="mt-6">Open scanner</ButtonLink></div></div>
  }

  const highRisk = result.riskScore >= 60
  const modelPct = (result.ml.phishingProbability * 100).toFixed(1)
  const legitimatePct = (result.ml.legitimateProbability * 100).toFixed(1)
  const externalUnavailable = result.threatIntelligence.status !== 'AVAILABLE' || result.threatIntelligence.coveragePercent < 100

  return <div className="mx-auto max-w-7xl">
    <div className="mb-8 flex items-center justify-between gap-4"><Link to="/scanner" className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-white"><ArrowLeft size={16}/> New scan</Link><div className="flex items-center gap-2 text-xs text-slate-500"><Clock3 size={14}/> {new Date(result.scannedAt).toLocaleString()}</div></div>

    <div className="panel overflow-hidden">
      <section className="border-b border-white/5 p-6 sm:p-8">
        <div className="flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0"><div className="eyebrow">Live multi-signal security analysis</div><h1 className="mt-3 break-all text-xl font-semibold text-white sm:text-2xl">{result.url}</h1><p className="mt-2 break-all text-xs text-slate-600">Normalized: {result.normalizedUrl}</p><p className="mt-1 text-xs text-slate-600">Domain: {result.domain}</p><div className="mt-4"><RiskBadge verdict={result.verdict}/></div></div>
          <div className="w-full max-w-xs xl:w-80"><div className="flex items-end justify-between"><span className="text-xs uppercase tracking-[0.14em] text-slate-500">Final risk score</span><span className="text-4xl font-bold text-white">{result.riskScore}<span className="text-lg text-slate-600">/100</span></span></div><div className="mt-3 h-2 overflow-hidden rounded-full bg-white/5"><div className={`h-full ${highRisk ? 'bg-rose-400' : result.riskScore >= 30 ? 'bg-amber-300' : 'bg-emerald-300'}`} style={{ width: `${Math.min(100, result.riskScore)}%` }}/></div><p className="mt-2 text-right text-xs text-slate-500">Coverage-aware risk engine</p></div>
        </div>
      </section>

      <section className="grid gap-3 p-6 sm:grid-cols-2 sm:p-8 lg:grid-cols-5">{Object.entries(result.signals).map(([key, value]) => <SignalCard key={key} label={formatSignalLabel(key)} value={value}/>)}</section>

      {externalUnavailable && <div className="mx-6 mb-2 flex gap-3 rounded-xl border border-amber-300/10 bg-amber-300/5 p-4 sm:mx-8"><Info size={17} className="mt-0.5 shrink-0 text-amber-300"/><div><div className="text-sm font-medium text-amber-100">Coverage notice</div><div className="mt-1 text-xs leading-5 text-slate-400">One or more enrichment providers were unavailable or unconfigured. Those sources were excluded from the weighted score rather than treated as clean.</div></div></div>}

      {highRisk && <section className="border-t border-white/5 bg-rose-400/[0.035] p-6 sm:p-8"><div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex items-center gap-2 text-rose-200"><ShieldAlert size={19}/><span className="text-sm font-semibold uppercase tracking-[0.12em]">Prevention warning</span></div><h2 className="mt-3 text-xl font-bold text-white">Do not trust this destination with sensitive information.</h2><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Avoid passwords, OTPs, payment details and authentication codes. Verify the organization using a trusted channel before interacting with the site.</p></div><ButtonLink to="/report" state={{ url: result.url }} variant="danger">Report phishing</ButtonLink></div></section>}

      <section className="grid gap-6 border-t border-white/5 p-6 sm:p-8 lg:grid-cols-[0.95fr_1.05fr]">
        <div><h2 className="text-lg font-semibold text-white">Why this result?</h2><div className="mt-4 space-y-3">{result.reasons.map((reason) => <div key={reason} className="flex gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-4"><AlertTriangle size={17} className="mt-0.5 shrink-0 text-amber-300"/><span className="text-sm leading-6 text-slate-300">{reason}</span></div>)}</div></div>
        <div className="rounded-2xl border border-sky-300/10 bg-sky-400/5 p-5"><div className="flex items-center gap-2 text-sky-200"><ShieldAlert size={18}/><h2 className="font-semibold">Recommendation</h2></div><p className="mt-3 text-sm leading-6 text-slate-300">{result.recommendation}</p><div className="mt-5 flex items-center gap-2 text-xs text-slate-500"><CheckCircle2 size={14} className="text-sky-300"/> {result.methodology}</div></div>
      </section>

      <section className="border-t border-white/5 p-6 sm:p-8"><div className="flex items-center gap-2"><Radar size={17} className="text-sky-300"/><h2 className="font-semibold text-white">Threat intelligence</h2><span className="ml-auto text-xs text-slate-500">{result.threatIntelligence.availableProviders}/{result.threatIntelligence.configuredProviders || 0} configured providers returned</span></div><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/5"><div className="h-full bg-sky-300" style={{ width: `${result.threatIntelligence.coveragePercent}%` }}/></div><div className="mt-5 grid gap-3 lg:grid-cols-2">{result.threatIntelligence.providers.map((provider) => <ProviderCard key={provider.provider} provider={provider}/>)}</div></section>

      <section className="grid gap-6 border-t border-white/5 p-6 sm:p-8 lg:grid-cols-3">
        <InfoPanel icon={Globe2} title="RDAP / Domain" status={result.domainIntelligence.rdap.status}><div className="grid grid-cols-2 gap-3 text-xs"><Datum label="Domain" value={result.domainIntelligence.rdap.registrableDomain ?? '—'}/><Datum label="Registrar" value={result.domainIntelligence.rdap.registrar ?? '—'}/><Datum label="Age" value={result.domainIntelligence.rdap.daysOld === null ? '—' : `${result.domainIntelligence.rdap.daysOld} days`}/><Datum label="Nameservers" value={result.domainIntelligence.rdap.nameservers.length ? String(result.domainIntelligence.rdap.nameservers.length) : '—'}/></div>{result.domainIntelligence.rdap.reasons.length > 0 && <p className="mt-4 text-xs leading-5 text-slate-500">{result.domainIntelligence.rdap.reasons[0]}</p>}</InfoPanel>
        <InfoPanel icon={Server} title="DNS" status={result.domainIntelligence.dns.status}><div className="grid grid-cols-2 gap-3 text-xs"><Datum label="IPv4" value={String(result.domainIntelligence.dns.ipv4.length)}/><Datum label="IPv6" value={String(result.domainIntelligence.dns.ipv6.length)}/><Datum label="MX" value={String(result.domainIntelligence.dns.mx.length)}/><Datum label="NS" value={String(result.domainIntelligence.dns.ns.length)}/></div>{result.domainIntelligence.dns.privateAddresses.length > 0 && <p className="mt-4 text-xs leading-5 text-amber-200">Private/reserved resolution detected; active network enrichment was blocked.</p>}</InfoPanel>
        <InfoPanel icon={LockKeyhole} title="TLS" status={result.domainIntelligence.tls.status}><div className="grid grid-cols-2 gap-3 text-xs"><Datum label="Authorized" value={result.domainIntelligence.tls.authorized === null ? '—' : result.domainIntelligence.tls.authorized ? 'Yes' : 'No'}/><Datum label="Issuer" value={result.domainIntelligence.tls.issuer ?? '—'}/><Datum label="Expires" value={result.domainIntelligence.tls.validTo ? new Date(result.domainIntelligence.tls.validTo).toLocaleDateString() : '—'}/><Datum label="Days left" value={result.domainIntelligence.tls.daysRemaining === null ? '—' : String(result.domainIntelligence.tls.daysRemaining)}/></div>{result.domainIntelligence.tls.reasons.length > 0 && <p className="mt-4 text-xs leading-5 text-slate-500">{result.domainIntelligence.tls.reasons[0]}</p>}</InfoPanel>
      </section>

      <section className="border-t border-white/5 p-6 sm:p-8"><div className="flex items-center gap-2"><Database size={17} className="text-sky-300"/><h2 className="font-semibold text-white">Risk engine breakdown</h2></div><div className="mt-5 grid gap-3 md:grid-cols-2 lg:grid-cols-5">{result.riskBreakdown.map((signal) => <div key={signal.name} className={`rounded-2xl border p-4 ${signal.included ? 'border-white/[0.07] bg-white/[0.02]' : 'border-white/5 bg-black/10 opacity-60'}`}><div className="flex items-center justify-between gap-3 text-xs"><span className="font-medium text-slate-300">{signal.name}</span><span className="font-mono text-slate-500">{signal.included ? `${signal.weight * 100}%` : 'excluded'}</span></div><div className="mt-3 text-2xl font-bold text-white">{signal.score}</div><div className="mt-2 text-[11px] leading-4 text-slate-600">{signal.rationale}</div></div>)}</div></section>

      <section className="grid gap-4 border-t border-white/5 p-6 sm:grid-cols-3 sm:p-8"><Metric title="Phishing probability" value={`${modelPct}%`} caption={result.ml.modelName}/><Metric title="Legitimate probability" value={`${legitimatePct}%`} caption={`Feature schema ${result.ml.featureVersion}`}/><Metric title="Persistence" value={result.persistence === 'PERSISTED' ? 'Stored' : 'Live only'} caption={result.persistence === 'PERSISTED' ? 'PostgreSQL scan record created' : 'Database unavailable; result returned live'}/></section>

      <section className="border-t border-white/5 p-6 sm:p-8"><div className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]"><div><div className="flex items-center gap-2"><Database size={17} className="text-sky-300"/><h2 className="font-semibold text-white">Model feature importance</h2></div><p className="mt-2 text-xs leading-5 text-slate-500">Global importance from the loaded model; it describes overall model reliance, not guaranteed causation for this individual URL.</p><div className="mt-4 space-y-2">{result.ml.topModelFeatures.slice(0, 6).map((item) => <div key={item.feature} className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3"><div className="flex items-center justify-between gap-4 text-xs"><span className="truncate text-slate-300">{item.feature.replaceAll('_', ' ')}</span><span className="font-mono text-slate-500">{(item.importance * 100).toFixed(1)}%</span></div><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/5"><div className="h-full bg-sky-300" style={{ width: `${Math.min(100, item.importance * 100 * 5)}%` }}/></div></div>)}</div></div><div><div className="flex items-center gap-2"><Database size={17} className="text-sky-300"/><h2 className="font-semibold text-white">Extracted feature snapshot</h2></div><div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{Object.entries(result.ml.features).map(([key, value]) => <div key={key} className="rounded-xl border border-white/[0.07] bg-black/10 p-3"><div className="truncate text-[10px] uppercase tracking-[0.12em] text-slate-600">{key.replaceAll('_', ' ')}</div><div className="mt-1 text-sm font-semibold text-slate-200">{typeof value === 'number' ? Number(value.toFixed(4)) : value}</div></div>)}</div></div></div></section>

      <section className="flex flex-col justify-between gap-4 border-t border-white/5 p-6 sm:flex-row sm:items-center sm:p-8"><div><div className="text-sm font-semibold text-white">Model trace</div><div className="mt-1 text-xs text-slate-500">{result.ml.modelName} · {result.modelVersion} · {Object.keys(result.ml.features).length} lexical features · {result.threatIntelligence.coveragePercent}% threat-intel coverage</div></div><ButtonLink to="/scanner">Scan another URL</ButtonLink></section>
    </div>
  </div>
}

function ProviderCard({ provider }: { provider: ScanResultType['threatIntelligence']['providers'][number] }) {
  const matched = provider.status === 'MATCHED'
  const suspicious = provider.status === 'SUSPICIOUS'
  const blocked = provider.status === 'BLOCKED'
  const rateLimited = provider.status === 'RATE_LIMITED'
  const stateClass = matched ? 'border-rose-300/10 bg-rose-300/5' : suspicious ? 'border-amber-300/10 bg-amber-300/5' : provider.status === 'NO_MATCH' ? 'border-emerald-300/10 bg-emerald-300/5' : blocked ? 'border-amber-300/10 bg-amber-300/5' : rateLimited ? 'border-amber-300/10 bg-amber-300/5' : 'border-white/[0.07] bg-white/[0.02]'
  return <div className={`rounded-2xl border p-4 ${stateClass}`}><div className="flex items-center justify-between gap-4"><div className="flex items-center gap-2"><Radar size={16} className="text-sky-300"/><span className="text-sm font-semibold text-white">{provider.provider}</span></div><span className="rounded-full bg-black/[0.15] px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">{provider.configured ? provider.status.replace('_', ' ') : 'NOT CONFIGURED'}</span></div><p className="mt-3 text-xs leading-5 text-slate-400">{provider.summary}</p><div className="mt-3 text-[10px] text-slate-600">Checked {new Date(provider.checkedAt).toLocaleTimeString()}</div></div>
}

function InfoPanel({ icon: Icon, title, status, children }: { icon: typeof Globe2; title: string; status: string; children: ReactNode }) {
  return <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5"><div className="flex items-center gap-2"><Icon size={17} className="text-sky-300"/><h2 className="font-semibold text-white">{title}</h2><span className="ml-auto text-[10px] uppercase tracking-[0.12em] text-slate-600">{status.replaceAll('_', ' ')}</span></div><div className="mt-4">{children}</div></div>
}

function Datum({ label, value }: { label: string; value: string }) { return <div className="rounded-xl border border-white/5 bg-black/10 p-3"><div className="text-[10px] uppercase tracking-[0.12em] text-slate-600">{label}</div><div className="mt-1 truncate text-sm font-medium text-slate-300">{value}</div></div> }
function Metric({ title, value, caption }: { title: string; value: string; caption: string }) { return <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5"><div className="text-[10px] uppercase tracking-[0.14em] text-slate-600">{title}</div><div className="mt-2 text-2xl font-bold text-white">{value}</div><div className="mt-1 text-xs text-slate-500">{caption}</div></div> }
function formatSignalLabel(key: string) { return key.replace(/([A-Z])/g, ' $1').replace(/^./, (value) => value.toUpperCase()) }
