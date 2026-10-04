import { Menu, X, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { ButtonLink } from './ui/Button'
import { Logo } from './Logo'
import { useAuth } from '../context/AuthContext'

const links = [
  { to: '/scanner', label: 'Scanner' },
  { to: '/how-it-works', label: 'How it works' },
  { to: '/awareness', label: 'Awareness' },
]

export function Navbar() {
  const [open, setOpen] = useState(false)
  const { user } = useAuth()
  return <header className="sticky top-0 z-50 border-b border-white/5 bg-slate-950/80 backdrop-blur-xl"><div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8"><Logo/><nav className="hidden items-center gap-7 md:flex">{links.map((link) => <NavLink key={link.to} to={link.to} className={({ isActive }) => `text-sm transition ${isActive ? 'text-white' : 'text-slate-400 hover:text-white'}`}>{link.label}</NavLink>)}</nav><div className="hidden items-center gap-2 md:flex">{user ? <><ButtonLink to="/dashboard" variant="ghost"><ShieldCheck size={15}/>Workspace</ButtonLink></> : <><ButtonLink to="/login" variant="ghost">Log in</ButtonLink><ButtonLink to="/register">Get started</ButtonLink></>}</div><button type="button" onClick={() => setOpen((value) => !value)} className="rounded-xl p-2 text-slate-300 hover:bg-white/5 md:hidden" aria-label="Toggle navigation" aria-expanded={open} aria-controls="mobile-navigation">{open ? <X size={22}/> : <Menu size={22}/>}</button></div>{open && <div id="mobile-navigation" className="border-t border-white/5 px-4 pb-4 md:hidden"><nav className="mx-auto flex max-w-7xl flex-col gap-1 pt-3">{links.map((link) => <Link key={link.to} to={link.to} onClick={() => setOpen(false)} className="rounded-xl px-3 py-3 text-sm text-slate-300 hover:bg-white/5 hover:text-white">{link.label}</Link>)}<div className="mt-2 grid grid-cols-2 gap-2">{user ? <ButtonLink to="/dashboard" onClick={() => setOpen(false)} className="w-full">Workspace</ButtonLink> : <><ButtonLink to="/login" onClick={() => setOpen(false)} variant="secondary" className="w-full">Log in</ButtonLink><ButtonLink to="/register" onClick={() => setOpen(false)} className="w-full">Get started</ButtonLink></>}</div></nav></div>}</header>
}
