import { ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'

export function Footer() {
  return (
    <footer className="border-t border-white/5 bg-slate-950">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 px-4 py-10 sm:px-6 md:flex-row md:items-center md:justify-between lg:px-8">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold text-white"><ShieldCheck size={18} className="text-sky-300" /> PhishGuard</div>
          <p className="mt-2 max-w-md text-sm leading-6 text-slate-500">A multi-layer phishing detection and prevention platform. Detection results are risk assessments, not absolute guarantees.</p>
        </div>
        <div className="flex gap-5 text-sm text-slate-500">
          <Link to="/how-it-works" className="hover:text-white">How it works</Link>
          <Link to="/awareness" className="hover:text-white">Awareness</Link>
          <Link to="/report" className="hover:text-white">Report phishing</Link>
        </div>
      </div>
    </footer>
  )
}
