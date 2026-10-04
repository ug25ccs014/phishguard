import { ArrowLeft, Database, Info, Link2, Radar, ScanSearch } from 'lucide-react'
import { Link } from 'react-router-dom'
import { ScanForm } from '../components/ScanForm'
import { SectionHeader } from '../components/SectionHeader'

export function Scanner() {
  return <div className="mx-auto max-w-5xl">
    <div className="mb-8"><Link to="/" className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-white"><ArrowLeft size={16}/> Back to home</Link></div>
    <SectionHeader headingLevel="h1" eyebrow="URL scanner" title="Analyze a link before you trust it." description="Paste a complete HTTP or HTTPS URL. PhishGuard now combines machine learning with URL heuristics, threat intelligence and domain/DNS/TLS enrichment when those providers are available."/>
    <div className="mt-8"><ScanForm compact /></div>
    <div className="mt-8 grid gap-4 md:grid-cols-3">
      <InfoCard icon={Link2} title="URL intelligence" body="The URL is normalized and scored using the versioned ML lexical model plus deterministic phishing heuristics."/>
      <InfoCard icon={Radar} title="Threat intelligence" body="Live provider adapters can query PhishTank, OpenPhish, Google Web Risk and optional VirusTotal without making provider failures look like clean results."/>
      <InfoCard icon={Database} title="Domain intelligence" body="RDAP, DNS and TLS signals enrich the scan without rendering or blindly fetching the submitted webpage."/>
    </div>
    <div className="mt-8 panel p-6"><div className="flex gap-3"><Info size={18} className="mt-0.5 text-sky-300"/><div><h3 className="font-semibold text-white">Current detection workflow</h3><p className="mt-2 text-sm leading-6 text-slate-400">Validation → normalization → feature extraction → ML inference → URL heuristics → threat-intelligence lookup → RDAP/DNS/TLS enrichment → coverage-aware Risk Engine → explainable result.</p><div className="mt-4 flex flex-wrap gap-2 text-xs text-slate-500"><span className="rounded-full bg-white/5 px-2.5 py-1">No absolute-safe guarantee</span><span className="rounded-full bg-white/5 px-2.5 py-1">Provider failures are explicit</span><span className="rounded-full bg-white/5 px-2.5 py-1">No arbitrary webpage fetch</span></div></div></div></div>
  </div>
}

function InfoCard({ icon: Icon, title, body }: { icon: typeof ScanSearch; title: string; body: string }) {
  return <div className="panel p-5"><Icon size={19} className="text-sky-300"/><h3 className="mt-4 font-semibold text-white">{title}</h3><p className="mt-2 text-sm leading-6 text-slate-400">{body}</p></div>
}
