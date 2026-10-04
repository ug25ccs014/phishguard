type Props = { label: string; value: string }
export function SignalCard({ label, value }: Props) {
  return (
    <div className="rounded-xl border border-white/[0.08] bg-white/[0.025] p-4">
      <div className="text-xs uppercase tracking-[0.14em] text-slate-500">{label}</div>
      <div className="mt-2 text-sm font-semibold text-slate-200">{value}</div>
    </div>
  )
}
