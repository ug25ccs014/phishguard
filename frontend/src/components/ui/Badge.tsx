import type { ReactNode } from 'react'

type Props = { children: ReactNode; tone?: 'green' | 'yellow' | 'red' | 'blue' | 'slate' | 'purple' }

const styles = {
  green: 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300',
  yellow: 'border-amber-400/20 bg-amber-400/10 text-amber-300',
  red: 'border-rose-400/20 bg-rose-400/10 text-rose-300',
  blue: 'border-sky-400/20 bg-sky-400/10 text-sky-300',
  slate: 'border-slate-400/20 bg-slate-400/10 text-slate-300',
  purple: 'border-violet-400/20 bg-violet-400/10 text-violet-300',
}

export function Badge({ children, tone = 'slate' }: Props) {
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium ${styles[tone]}`}>{children}</span>
}
