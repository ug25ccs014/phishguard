import type { LucideIcon } from 'lucide-react'
import { ArrowDown, Brackets, Database, FileSearch, GitBranch, Globe2, ShieldAlert, Sparkles } from 'lucide-react'
import { SectionHeader } from '../components/SectionHeader'

const stages: Array<[string, string, string, LucideIcon]> = [
  ['01', 'Input validation', 'Accept only correctly structured HTTP/HTTPS URLs and reject malformed or unsupported input.', FileSearch],
  ['02', 'Normalization', 'Canonicalize the URL and isolate hostname, path, query and other components for consistent analysis.', Brackets],
  ['03', 'Signal extraction', 'Compute URL heuristics, domain characteristics and later DNS/TLS and reputation signals.', GitBranch],
  ['04', 'Detection', 'Run the versioned ML model while keeping threat intelligence and deterministic rules as separate evidence.', Sparkles],
  ['05', 'Risk engine', 'Combine signals into a configurable risk assessment without pretending any single source is infallible.', ShieldAlert],
  ['06', 'Response', 'Present the verdict, evidence and recommendation, then record the scan for authenticated history and review workflows.', Database],
]

export function HowItWorks() {
  return <div className="mx-auto max-w-6xl"><SectionHeader headingLevel="h1" eyebrow="Detection pipeline" title="One scan, multiple independent signals." description="The architecture separates collection, detection and decision-making so individual services can evolve without rewriting the product." align="center"/><div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">{stages.map(([number, title, body, Icon]) => { const StageIcon = Icon as typeof Globe2; return <div key={number} className="panel relative p-6"><div className="flex items-center justify-between"><span className="font-mono text-xs text-slate-600">{number}</span><StageIcon size={19} className="text-sky-300"/></div><h3 className="mt-8 text-lg font-semibold text-white">{title}</h3><p className="mt-2 text-sm leading-6 text-slate-400">{body}</p></div>})}</div><div className="mx-auto mt-10 hidden max-w-2xl items-center justify-center gap-3 text-xs text-slate-600 md:flex"><ArrowDown size={15}/><span>The live platform connects ML, intelligence providers and authenticated history through this pipeline.</span><ArrowDown size={15}/></div><div className="mt-10 rounded-2xl border border-white/[0.07] bg-white/[0.025] p-6 font-mono text-xs leading-8 text-slate-500 sm:p-8"><div className="text-sky-200">USER</div><div>↓</div><div>FRONTEND → BACKEND API</div><div>↓</div><div>VALIDATE → NORMALIZE → EXTRACT</div><div>↓</div><div>URL HEURISTICS + DOMAIN + DNS/TLS + THREAT INTELLIGENCE + MACHINE LEARNING</div><div>↓</div><div className="text-sky-200">RISK ENGINE → EXPLAINABILITY → FINAL RESULT</div><div>↓</div><div>LOW RISK / SUSPICIOUS / HIGH RISK / LIKELY PHISHING / KNOWN MALICIOUS</div></div></div>
}
