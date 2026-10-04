type Props = { label: string; value: string; hint: string }
export function StatCard({ label, value, hint }: Props) {
  return (
    <div className="panel p-5">
      <div className="text-sm text-slate-500">{label}</div>
      <div className="mt-2 text-3xl font-bold tracking-tight text-white">{value}</div>
      <div className="mt-2 text-xs text-slate-500">{hint}</div>
    </div>
  )
}
