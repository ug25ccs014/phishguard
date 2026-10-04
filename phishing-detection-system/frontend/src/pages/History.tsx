import { ChevronLeft, ChevronRight, ExternalLink, Search, Trash2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { RiskBadge } from '../components/RiskBadge'
import { Button } from '../components/ui/Button'
import { apiErrorMessage, deleteStoredScan, getScanHistory } from '../services/api'
import type { RiskLevel, ScanHistoryResponse } from '../types'

const verdicts = ['', 'LOW RISK', 'SUSPICIOUS', 'HIGH RISK', 'LIKELY PHISHING', 'KNOWN MALICIOUS']

export function History() {
  const [query, setQuery] = useState('')
  const [verdict, setVerdict] = useState('')
  const [page, setPage] = useState(1)
  const [data, setData] = useState<ScanHistoryResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const response = await getScanHistory({
        page,
        pageSize: 15,
        search: query || undefined,
        verdict: verdict || undefined,
      })
      setData(response)
    } catch (e) {
      setError(apiErrorMessage(e, 'Could not load scan history.'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), query ? 300 : 0)
    return () => window.clearTimeout(timer)
  }, [page, verdict, query])

  const remove = async (id: string) => {
    if (!window.confirm('Delete this saved scan from your history?')) return
    try {
      await deleteStoredScan(id)
      await load()
    } catch (e) {
      setError(apiErrorMessage(e, 'Could not delete the scan.'))
    }
  }

  return (
    <div className="mx-auto max-w-7xl">
      <div>
        <div className="eyebrow">Activity</div>
        <h1 className="mt-2 text-3xl font-bold text-white">Scan history</h1>
        <p className="mt-2 text-sm text-slate-500">Search and review scans saved to your account.</p>
      </div>

      <div className="panel mt-8 overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-white/5 p-5 lg:flex-row">
          <div className="relative flex-1">
            <Search size={17} className="absolute left-3 top-3.5 text-slate-600" />
            <label htmlFor="history-search" className="sr-only">Search URLs or domains</label>
            <input
              id="history-search"
              value={query}
              onChange={(e) => { setQuery(e.target.value); setPage(1) }}
              placeholder="Search URLs or domains"
              className="w-full rounded-xl border border-white/10 bg-white/[0.025] py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-sky-300/30"
            />
          </div>
          <label htmlFor="history-verdict" className="sr-only">Filter by verdict</label>
          <select
            id="history-verdict"
            value={verdict}
            onChange={(e) => { setVerdict(e.target.value); setPage(1) }}
            className="rounded-xl border border-white/10 bg-slate-950 px-3 py-3 text-sm text-slate-300 outline-none focus:border-sky-300/30"
          >
            <option value="">All verdicts</option>
            {verdicts.slice(1).map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
        </div>

        {error && <div className="border-b border-rose-300/10 bg-rose-400/5 p-4 text-sm text-rose-200">{error}</div>}

        {loading ? (
          <div className="p-10 text-center text-sm text-slate-500">Loading history…</div>
        ) : data ? (
          <>
            {data.items.length ? (
              <div className="divide-y divide-white/5">
                <div className="hidden grid-cols-[1fr_170px_90px_170px_48px] gap-5 px-5 py-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-600 sm:grid">
                  <span>URL</span><span>Verdict</span><span>Risk</span><span>Scanned</span><span />
                </div>
                {data.items.map((row) => (
                  <div key={row.id} className="grid gap-3 px-5 py-5 sm:grid-cols-[1fr_170px_90px_170px_48px] sm:items-center sm:gap-5">
                    <Link to={`/scan-result/${row.id}`} className="min-w-0 hover:text-white">
                      <div className="truncate text-sm text-slate-200">{row.url}</div>
                      <div className="mt-1 text-xs text-slate-600">{row.domain} · {row.id.slice(0, 10)}</div>
                    </Link>
                    <div>{row.verdict && <RiskBadge verdict={row.verdict as RiskLevel} />}</div>
                    <div className="text-sm font-semibold text-slate-300">{row.riskScore}/100</div>
                    <div className="text-xs text-slate-500">{new Date(row.scannedAt).toLocaleString()}</div>
                    <button
                      onClick={() => void remove(row.id)}
                      className="justify-self-start rounded-lg p-2 text-slate-600 hover:bg-rose-400/10 hover:text-rose-300"
                      aria-label={`Delete scan ${row.id}`}
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-10 text-center">
                <div className="text-sm text-slate-300">No saved scans found.</div>
                <Link to="/scanner" className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-sky-300 hover:text-sky-200">
                  Scan a URL <ExternalLink size={14} />
                </Link>
              </div>
            )}

            <div className="flex items-center justify-between border-t border-white/5 p-4">
              <span className="text-xs text-slate-600">{data.pagination.total} total scans</span>
              <div className="flex items-center gap-2">
                <Button variant="secondary" aria-label="Previous page" disabled={data.pagination.page <= 1} onClick={() => setPage((v) => Math.max(1, v - 1))}><ChevronLeft size={15} aria-hidden="true" /></Button>
                <span className="text-xs text-slate-500">Page {data.pagination.page} / {data.pagination.totalPages}</span>
                <Button variant="secondary" aria-label="Next page" disabled={data.pagination.page >= data.pagination.totalPages} onClick={() => setPage((v) => v + 1)}><ChevronRight size={15} aria-hidden="true" /></Button>
              </div>
            </div>
          </>
        ) : null}
      </div>
    </div>
  )
}
