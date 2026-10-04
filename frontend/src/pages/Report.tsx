import { FileWarning, Send } from 'lucide-react'
import { useEffect, useState, type ChangeEvent, type FormEvent } from 'react'
import { useLocation } from 'react-router-dom'
import { Button } from '../components/ui/Button'
import { apiErrorMessage, createReport, getMyReports } from '../services/api'
import type { PhishingReport } from '../types'

export function Report() {
  const location = useLocation()
  const prefilledUrl = (location.state as { url?: string } | null)?.url ?? ''
  const [url, setUrl] = useState(prefilledUrl)
  const [category, setCategory] = useState('credential')
  const [description, setDescription] = useState('')
  const [reports, setReports] = useState<PhishingReport[]>([])
  const [reportsLoading, setReportsLoading] = useState(true)
  const [reportsError, setReportsError] = useState('')
  const [sent, setSent] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const load = () => { setReportsLoading(true); setReportsError(''); return getMyReports().then((result) => setReports(result.items)).catch((error) => setReportsError(apiErrorMessage(error, 'Could not load your reports.'))).finally(() => setReportsLoading(false)) }
  useEffect(() => { void load() }, [])

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError(''); setSent(''); setLoading(true)
    try { const result = await createReport({ url: url.trim(), category, description: description.trim() || undefined }); setSent(`Report ${result.id.slice(0, 10)} submitted for review.`); setUrl(''); setDescription(''); load() }
    catch (e) { setError(apiErrorMessage(e, 'Could not submit the report.')) }
    finally { setLoading(false) }
  }

  return <div className="mx-auto max-w-4xl"><div><div className="eyebrow">Community reporting</div><h1 className="mt-2 text-3xl font-bold text-white">Report suspicious phishing</h1><p className="mt-2 text-sm leading-6 text-slate-500">Submit a URL for review. Never include passwords, tokens, private keys or other secrets.</p></div><form onSubmit={submit} className="panel mt-8 p-6 sm:p-8"><div className="flex items-start gap-4"><div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-rose-400/10 text-rose-300"><FileWarning size={19}/></div><div><h2 className="font-semibold text-white">Tell us what you found</h2><p className="mt-1 text-xs leading-5 text-slate-500">Reports are linked to your account and reviewed in the admin queue.</p></div></div><div className="mt-7 space-y-5"><Field id="report-url" label="Suspicious URL" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://suspicious.example/login"/><div><label htmlFor="report-category" className="mb-2 block text-xs font-medium text-slate-400">Category</label><select id="report-category" value={category} onChange={(e) => setCategory(e.target.value)} className="w-full rounded-xl border border-white/10 bg-slate-950 py-3 px-3 text-sm text-slate-200 outline-none focus:border-sky-300/30"><option value="credential">Fake login / credential theft</option><option value="payment">Payment / financial scam</option><option value="impersonation">Brand impersonation</option><option value="malware">Malware delivery</option><option value="qr-phishing">QR phishing</option><option value="other">Other</option></select></div><div><label htmlFor="report-description" className="mb-2 block text-xs font-medium text-slate-400">Description</label><textarea id="report-description" value={description} onChange={(e) => setDescription(e.target.value)} rows={5} maxLength={2000} placeholder="What made the link suspicious?" className="w-full resize-none rounded-xl border border-white/10 bg-white/[0.035] px-3 py-3 text-sm text-white outline-none focus:border-sky-300/30"/></div><Button type="submit" loading={loading}><Send size={16}/> Submit report</Button>{error && <div className="rounded-xl border border-rose-300/10 bg-rose-400/5 p-4 text-sm text-rose-200" role="alert">{error}</div>}{sent && <div className="rounded-xl border border-emerald-300/10 bg-emerald-400/5 p-4 text-sm text-emerald-200" role="status">{sent}</div>}</div></form><section className="mt-8"><div className="eyebrow">Your reports</div>{reportsError && <div className="mt-3 rounded-xl border border-rose-300/10 bg-rose-400/5 p-4 text-sm text-rose-200" role="alert">{reportsError}</div>}<div className="mt-3 space-y-3">{reportsLoading ? <div className="panel p-8 text-center text-sm text-slate-500">Loading your reports…</div> : reports.length ? reports.map((report) => <div key={report.id} className="panel p-5"><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="truncate text-sm font-medium text-slate-200">{report.url}</div><div className="mt-1 text-xs text-slate-600">{report.category} · {new Date(report.createdAt).toLocaleString()}</div></div><span className="rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">{report.status}</span></div>{report.reviewNote && <p className="mt-4 text-xs leading-5 text-slate-500">Review note: {report.reviewNote}</p>}</div>) : <div className="panel p-8 text-center text-sm text-slate-500">No reports yet.</div>}</div></section></div>
}
function Field({ label, id, placeholder, value, onChange }: { id: string; label: string; placeholder: string; value: string; onChange: (event: ChangeEvent<HTMLInputElement>) => void }) { return <div><label htmlFor={id} className="mb-2 block text-xs font-medium text-slate-400">{label}</label><input id={id} required value={value} onChange={onChange} placeholder={placeholder} maxLength={4096} className="w-full rounded-xl border border-white/10 bg-white/[0.035] px-3 py-3 text-sm text-white outline-none focus:border-sky-300/30"/></div> }
