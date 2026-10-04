import { ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <Link to="/" className="group flex items-center gap-2.5" aria-label="PhishGuard home">
      <span className="grid h-9 w-9 place-items-center rounded-xl border border-sky-300/20 bg-sky-400/10 text-sky-300 shadow-glow transition group-hover:bg-sky-400/[0.15]">
        <ShieldCheck size={20} />
      </span>
      {!compact && <span className="font-bold tracking-tight text-white">PhishGuard<span className="text-sky-300">.</span></span>}
    </Link>
  )
}
