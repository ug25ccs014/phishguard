import type { LucideIcon } from 'lucide-react'

type Props = { icon: LucideIcon; title: string; description: string }
export function FeatureCard({ icon: Icon, title, description }: Props) {
  return (
    <div className="panel p-5 transition hover:-translate-y-0.5 hover:border-sky-300/[0.15]">
      <div className="mb-4 grid h-10 w-10 place-items-center rounded-xl bg-sky-400/10 text-sky-300"><Icon size={19} /></div>
      <h3 className="font-semibold text-white">{title}</h3>
      <p className="mt-2 text-sm leading-6 text-slate-400">{description}</p>
    </div>
  )
}
