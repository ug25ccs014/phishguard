import { Eye, EyeOff, LockKeyhole, Mail, ShieldCheck, UserRound } from 'lucide-react'
import { useEffect, useState, type FormEvent, type InputHTMLAttributes } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Button } from '../components/ui/Button'
import { useAuth } from '../context/AuthContext'
import { apiErrorMessage } from '../services/api'
import { safeInternalDestination } from '../utils/navigation'

export function AuthPage({ mode }: { mode: 'login' | 'register' }) {
  const [showPassword, setShowPassword] = useState(false)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const passwordChanged = (location.state as { passwordChanged?: boolean } | null)?.passwordChanged
  const { user, login, register } = useAuth()
  const isLogin = mode === 'login'

  useEffect(() => { if (user) navigate('/dashboard', { replace: true }) }, [user, navigate])

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setMessage(''); setLoading(true)
    try {
      if (isLogin) await login({ email, password })
      else await register({ name, email, password })
      const destination = safeInternalDestination((location.state as { from?: unknown } | null)?.from)
      navigate(destination, { replace: true })
    } catch (error) { setMessage(apiErrorMessage(error, isLogin ? 'Unable to sign in.' : 'Unable to create the account.')) }
    finally { setLoading(false) }
  }

  return <div className="min-h-[calc(100vh-4rem)] bg-grid bg-[size:42px_42px] px-4 py-14 sm:px-6"><div className="mx-auto grid max-w-5xl overflow-hidden rounded-3xl border border-white/10 bg-slate-950 shadow-2xl shadow-black/30 md:grid-cols-2"><div className="hidden border-r border-white/5 bg-sky-400/[0.025] p-10 md:block"><div className="eyebrow">Security workspace</div><h1 className="mt-4 text-4xl font-bold tracking-tight text-white">Your phishing defense console.</h1><p className="mt-4 text-sm leading-7 text-slate-400">Create a protected workspace for scan history, phishing reports and personalized security settings.</p><div className="mt-10 space-y-3"><div className="flex items-center gap-3 text-sm text-slate-300"><ShieldCheck size={18} className="text-sky-300"/> Multi-signal analysis</div><div className="flex items-center gap-3 text-sm text-slate-300"><LockKeyhole size={18} className="text-sky-300"/> Secure session cookies + CSRF protection</div><div className="flex items-center gap-3 text-sm text-slate-300"><UserRound size={18} className="text-sky-300"/> Personal scan history</div></div></div><div className="p-6 sm:p-10"><div className="eyebrow">{isLogin ? 'Welcome back' : 'Create workspace'}</div><h2 className="mt-2 text-2xl font-bold text-white">{isLogin ? 'Log in to PhishGuard' : 'Create your account'}</h2><p className="mt-2 text-sm text-slate-500">{isLogin ? 'Use your PhishGuard credentials to access your secure workspace.' : 'Password must be at least 10 characters.'}</p>{passwordChanged && <div className="mt-4 rounded-xl border border-emerald-300/10 bg-emerald-400/5 p-3 text-xs text-emerald-200">Password changed successfully. Please sign in again.</div>}<form onSubmit={submit} className="mt-7 space-y-4">{!isLogin && <div><label htmlFor="auth-name" className="mb-2 block text-xs font-medium text-slate-400">Name</label><div className="relative"><UserRound className="absolute left-3 top-3.5 text-slate-600" size={17}/><input id="auth-name" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} required minLength={2} maxLength={80} placeholder="Your name" className="w-full rounded-xl border border-white/10 bg-white/[0.035] py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-sky-300/30 focus:ring-2 focus:ring-sky-300/10"/></div></div>}<Field id="auth-email" label="Email" icon={Mail} autoComplete="email" autoCapitalize="none" spellCheck={false} value={email} onChange={(e) => setEmail(e.target.value)} type="email" placeholder="you@example.com" required maxLength={254} /><div><label htmlFor="auth-password" className="mb-2 block text-xs font-medium text-slate-400">Password</label><div className="relative"><LockKeyhole className="absolute left-3 top-3.5 text-slate-600" size={17}/><input id="auth-password" autoComplete={isLogin ? "current-password" : "new-password"} value={password} onChange={(e) => setPassword(e.target.value)} type={showPassword ? 'text' : 'password'} required minLength={isLogin ? 1 : 10} maxLength={128} placeholder="••••••••" className="w-full rounded-xl border border-white/10 bg-white/[0.035] py-3 pl-10 pr-11 text-sm text-white outline-none focus:border-sky-300/30 focus:ring-2 focus:ring-sky-300/10"/><button type="button" onClick={() => setShowPassword((value) => !value)} className="absolute right-2 top-2 rounded-lg p-2 text-slate-500 hover:text-white" aria-label="Toggle password visibility">{showPassword ? <EyeOff size={17}/> : <Eye size={17}/>}</button></div></div><Button type="submit" loading={loading} className="mt-2 w-full">{isLogin ? 'Log in' : 'Create account'}</Button>{message && <p role="alert" className="rounded-xl border border-rose-300/10 bg-rose-400/5 p-3 text-xs leading-5 text-rose-200">{message}</p>}</form><p className="mt-6 text-center text-xs text-slate-500">{isLogin ? 'New here?' : 'Already have an account?'} <Link to={isLogin ? '/register' : '/login'} className="font-semibold text-sky-300 hover:text-sky-200">{isLogin ? 'Create an account' : 'Log in'}</Link></p></div></div></div>
}

function Field({ label, icon: Icon, id, ...props }: { label: string; icon: typeof Mail } & InputHTMLAttributes<HTMLInputElement>) {
  return <div><label htmlFor={id} className="mb-2 block text-xs font-medium text-slate-400">{label}</label><div className="relative"><Icon className="absolute left-3 top-3.5 text-slate-600" size={17}/><input id={id} {...props} className="w-full rounded-xl border border-white/10 bg-white/[0.035] py-3 pl-10 pr-3 text-sm text-white outline-none focus:border-sky-300/30 focus:ring-2 focus:ring-sky-300/10"/></div></div>
}
