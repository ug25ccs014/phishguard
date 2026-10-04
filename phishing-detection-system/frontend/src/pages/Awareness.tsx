import { AlertCircle, CheckCircle2, Fingerprint, KeyRound, MailWarning, QrCode, Smartphone, ShieldQuestion } from 'lucide-react'
import { SectionHeader } from '../components/SectionHeader'

const cards = [
  [AlertCircle, 'Urgency is a signal', 'Messages that pressure you to act immediately deserve extra verification. Attackers often use fear, urgency or reward to bypass careful review.'],
  [Fingerprint, 'Check the real domain', 'Look at the registrable domain instead of trusting brand-like words buried deep inside a long URL.'],
  [KeyRound, 'Protect credentials', 'Never enter passwords, OTPs or payment details on a site you have not independently verified.'],
  [MailWarning, 'Inspect email context', 'Sender names can be spoofed or made to look familiar. Treat unexpected login, payment or account messages carefully.'],
  [QrCode, 'QR links can hide destinations', 'A QR code is still a link. Decode it and inspect the destination before opening or signing in.'],
  [Smartphone, 'Smishing works the same way', 'SMS phishing uses the same trust tricks as email phishing. Verify delivery, payment and account messages through official channels.'],
]

export function Awareness() {
  return <div className="mx-auto max-w-6xl"><SectionHeader headingLevel="h1" eyebrow="Security awareness" title="Learn the signals before you need the scanner." description="The prevention side of the platform is designed to help users recognize suspicious behavior even when a detector has not seen a threat before." align="center"/><div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">{cards.map(([Icon, title, body]) => { const I = Icon as typeof ShieldQuestion; return <article key={title as string} className="panel p-6"><I size={20} className="text-sky-300"/><h3 className="mt-5 font-semibold text-white">{title as string}</h3><p className="mt-2 text-sm leading-6 text-slate-400">{body as string}</p></article>})}</div><div className="mt-8 grid gap-4 md:grid-cols-2"><div className="panel p-6"><h3 className="text-lg font-semibold text-white">Before you click</h3><div className="mt-4 space-y-3">{['Hover or inspect the destination when possible.', 'Look for misspellings and unexpected domain changes.', 'Use a trusted, independently opened channel to verify requests.', 'Do not provide sensitive data just because a page looks polished.'].map((item) => <div key={item} className="flex gap-3 text-sm leading-6 text-slate-400"><CheckCircle2 size={16} className="mt-1 shrink-0 text-emerald-300"/>{item}</div>)}</div></div><div className="panel p-6"><h3 className="text-lg font-semibold text-white">What the scanner can and cannot say</h3><p className="mt-3 text-sm leading-6 text-slate-400">A low-risk result means no known high-risk indicator was detected by the available signals. It is not a guarantee of safety. A high-risk result is a warning to stop and verify before providing information.</p></div></div></div>
}
