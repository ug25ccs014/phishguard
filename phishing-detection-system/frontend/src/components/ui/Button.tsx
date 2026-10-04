import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Link, type LinkProps } from 'react-router-dom'

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  loading?: boolean
}

const variantClass: Record<ButtonVariant, string> = {
  primary: 'bg-sky-400 text-slate-950 shadow-lg shadow-sky-500/20 hover:bg-sky-300',
  secondary: 'border border-white/10 bg-white/[0.06] text-white hover:bg-white/10',
  ghost: 'text-slate-300 hover:bg-white/[0.06] hover:text-white',
  danger: 'bg-rose-500 text-white hover:bg-rose-400',
}

export function Button({ variant = 'primary', loading = false, className = '', children, disabled, type = 'button', ...props }: Props) {
  return (
    <button
      {...props}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={`inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition focus:outline-none focus:ring-2 focus:ring-sky-300/50 disabled:cursor-not-allowed disabled:opacity-50 ${variantClass[variant]} ${className}`}
    >
      {loading ? <><span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden="true" /><span className="sr-only">Loading</span></> : null}
      {children}
    </button>
  )
}

export type ButtonLinkProps = Omit<LinkProps, 'className'> & {
  variant?: ButtonVariant
  className?: string
  children: ReactNode
}

export function ButtonLink({ variant = 'primary', className = '', children, ...props }: ButtonLinkProps) {
  return <Link {...props} className={`inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition focus:outline-none focus:ring-2 focus:ring-sky-300/50 ${variantClass[variant]} ${className}`}>{children}</Link>
}
