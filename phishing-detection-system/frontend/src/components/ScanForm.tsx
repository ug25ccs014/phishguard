import { Search, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiErrorMessage, scanUrl } from '../services/api'
import { Button } from './ui/Button'

export function ScanForm({ compact = false }: { compact?: boolean }) {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const submit = async (event: { preventDefault(): void }) => {
    event.preventDefault()
    const candidate = url.trim()
    if (!candidate) {
      setError('Enter a URL to analyze.')
      return
    }
    try {
      const parsed = new URL(candidate)
      if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error('unsupported')
    } catch {
      setError('Enter a complete HTTP or HTTPS URL, for example https://example.com')
      return
    }

    setError('')
    setLoading(true)
    try {
      const result = await scanUrl(candidate)
      navigate('/scan-result', { state: { result } })
    } catch (requestError) {
      setError(apiErrorMessage(requestError, 'The scan could not be completed. Please check the URL and try again.'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={submit} className={`panel ${compact ? 'p-4' : 'p-2 sm:p-3'}`}>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="flex min-w-0 flex-1 items-center gap-3 px-3 py-2">
          <Search size={19} className="shrink-0 text-sky-300" />
          <input id="url-scan-input" value={url} maxLength={4096} autoComplete="off" spellCheck={false} inputMode="url" onChange={(event: { target: { value: string } }) => { setUrl(event.target.value); if (error) setError('') }} aria-invalid={Boolean(error)} aria-describedby={error ? "url-scan-help url-scan-error" : "url-scan-help"} placeholder="Paste a suspicious URL…" className="w-full bg-transparent py-2 text-sm text-white outline-none placeholder:text-slate-600" aria-label="Suspicious URL" />
        </div>
        <Button type="submit" loading={loading} className="w-full sm:w-auto"><ShieldAlert size={17} />Analyze URL</Button>
      </div>
      {error && <p id="url-scan-error" className="px-3 pb-2 text-sm text-rose-300" role="alert">{error}</p>}
      <div id="url-scan-help" aria-live="polite" className="px-3 pt-2 text-xs text-slate-600">Live scan: ML, URL heuristics, threat intelligence, RDAP and DNS/TLS enrichment are combined when providers are available.</div>
    </form>
  )
}
