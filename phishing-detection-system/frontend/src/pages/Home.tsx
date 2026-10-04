import { ArrowRight, Bot, CheckCircle2, DatabaseZap, Fingerprint, Globe2, Radar, ShieldAlert, ShieldCheck, Sparkles, TerminalSquare } from 'lucide-react'
import { Link } from 'react-router-dom'
import { FeatureCard } from '../components/FeatureCard'
import { ScanForm } from '../components/ScanForm'
import { SectionHeader } from '../components/SectionHeader'
import { ButtonLink } from '../components/ui/Button'

const featureCards = [
  { icon: Bot, title: 'Machine-learning detection', description: 'A dedicated inference service classifies URL signals using the versioned phishing model.' },
  { icon: Radar, title: 'Threat intelligence', description: 'Cross-check suspicious links against modular reputation and phishing intelligence providers.' },
  { icon: Globe2, title: 'Domain intelligence', description: 'Enrich analysis with RDAP, DNS, TLS and domain-level indicators where available.' },
  { icon: Fingerprint, title: 'Explainable results', description: 'Show the signals behind a verdict instead of exposing a black-box yes/no prediction.' },
  { icon: ShieldAlert, title: 'Prevention first', description: 'High-risk findings lead with warnings and practical guidance before sensitive data is entered.' },
  { icon: DatabaseZap, title: 'Audit-ready history', description: 'Store scan outcomes, model versions and reports for future investigation and review.' },
]

export function Home() {
  return <>
    <section className="relative overflow-hidden border-b border-white/5 bg-grid bg-[size:42px_42px]">
      <div className="absolute inset-x-0 top-0 h-80 bg-sky-500/10 blur-3xl" />
      <div className="relative mx-auto max-w-7xl px-4 pb-20 pt-20 sm:px-6 sm:pt-24 lg:px-8 lg:pb-28">
        <div className="max-w-3xl">
          <div className="eyebrow mb-4 flex items-center gap-2"><Sparkles size={14}/> Multi-layer phishing defense</div>
          <h1 className="text-5xl font-bold leading-[1.05] tracking-tight sm:text-6xl lg:text-7xl"><span className="gradient-text">Detect phishing</span><br/>before it detects you.</h1>
          <p className="mt-6 max-w-2xl text-base leading-8 text-slate-400 sm:text-lg">Analyze suspicious links using URL heuristics, machine learning, threat intelligence, domain intelligence and a dedicated risk engine.</p>
          <div className="mt-9 max-w-3xl"><ScanForm /></div>
          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-xs text-slate-500"><span className="flex items-center gap-1.5"><CheckCircle2 size={14} className="text-emerald-300"/> HTTP/HTTPS URL validation</span><span className="flex items-center gap-1.5"><CheckCircle2 size={14} className="text-emerald-300"/> Explainable assessments</span><span className="flex items-center gap-1.5"><CheckCircle2 size={14} className="text-emerald-300"/> Prevention-focused UX</span></div>
        </div>
        <div className="mt-14 grid gap-4 sm:grid-cols-3">
          {[['5', 'detection signal families'], ['5', 'risk states'], ['1', 'unified security report']].map(([v, l]) => <div key={l} className="glass rounded-2xl p-5"><div className="text-3xl font-bold text-white">{v}</div><div className="mt-1 text-sm text-slate-500">{l}</div></div>)}
        </div>
      </div>
    </section>

    <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8"><SectionHeader eyebrow="Architecture" title="Five signals. One security decision." description="The platform treats machine learning as one signal among several, making the analysis more transparent and easier to evolve."/><div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">{featureCards.map((feature) => <FeatureCard key={feature.title} {...feature} />)}</div></section>

    <section className="border-y border-white/5 bg-white/[0.02]"><div className="mx-auto grid max-w-7xl gap-10 px-4 py-20 sm:px-6 lg:grid-cols-2 lg:px-8"><div><SectionHeader eyebrow="How it works" title="A layered pipeline built for security." description="Every scan flows through validation and normalization before analysis. The live pipeline connects the real ML and intelligence services through this foundation."/><Link to="/how-it-works" className="mt-7 inline-flex items-center gap-2 text-sm font-semibold text-sky-300 hover:text-sky-200">Explore the pipeline <ArrowRight size={16}/></Link></div><div className="panel overflow-hidden p-5"><div className="space-y-3 font-mono text-sm"><div className="rounded-xl border border-white/[0.07] bg-black/20 p-3 text-slate-400">01 &nbsp; USER INPUT <span className="float-right text-slate-600">URL</span></div><div className="pl-6 text-slate-700">↓</div><div className="rounded-xl border border-white/[0.07] bg-black/20 p-3 text-slate-300">02 &nbsp; VALIDATE + NORMALIZE <span className="float-right text-slate-600">SECURE INPUT</span></div><div className="pl-6 text-slate-700">↓</div><div className="rounded-xl border border-sky-300/10 bg-sky-400/5 p-3 text-sky-200">03 &nbsp; EXTRACT + ENRICH <span className="float-right text-sky-400/60">SIGNALS</span></div><div className="pl-6 text-slate-700">↓</div><div className="rounded-xl border border-white/[0.07] bg-black/20 p-3 text-slate-300">04 &nbsp; RISK ENGINE <span className="float-right text-slate-600">DECISION</span></div><div className="pl-6 text-slate-700">↓</div><div className="rounded-xl border border-emerald-300/10 bg-emerald-400/5 p-3 text-emerald-200">05 &nbsp; RESULT + PREVENTION <span className="float-right text-emerald-400/60">ACTION</span></div></div></div></div></section>

    <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8"><div className="panel flex flex-col gap-6 p-7 sm:p-9 lg:flex-row lg:items-center lg:justify-between"><div><div className="eyebrow">Built to grow</div><h2 className="mt-2 text-2xl font-bold text-white">From a URL scanner to a security platform.</h2><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">The architecture leaves clean extension points for email analysis, QR phishing, webpage inspection and a future browser extension without forcing them into the first release.</p></div><ButtonLink to="/register">Open the workspace <ArrowRight size={16}/></ButtonLink></div></section>

    <section className="mx-auto max-w-7xl px-4 pb-20 sm:px-6 lg:px-8"><div className="grid gap-4 md:grid-cols-3"><div className="panel p-6"><TerminalSquare className="text-sky-300"/><h3 className="mt-5 font-semibold text-white">Security-minded backend</h3><p className="mt-2 text-sm leading-6 text-slate-400">Validation, structured errors, security headers and future SSRF-safe scanning boundaries are part of the design.</p></div><div className="panel p-6"><ShieldCheck className="text-sky-300"/><h3 className="mt-5 font-semibold text-white">No absolute-safe claims</h3><p className="mt-2 text-sm leading-6 text-slate-400">Results are framed as risk assessments with transparent limitations rather than false certainty.</p></div><div className="panel p-6"><Sparkles className="text-sky-300"/><h3 className="mt-5 font-semibold text-white">Demo-ready UX</h3><p className="mt-2 text-sm leading-6 text-slate-400">The frontend is connected to the live scan engine, with authenticated workspace features and operational controls built into the platform.</p></div></div></section>
  </>
}
