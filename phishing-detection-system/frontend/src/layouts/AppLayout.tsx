import { Activity, FileWarning, History, LayoutDashboard, LogOut, Menu, ScanSearch, Settings, ShieldCheck, X } from 'lucide-react'
import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { Logo } from '../components/Logo'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { useAuth } from '../context/AuthContext'
import { SkipLink } from '../components/SkipLink'

const items = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard },
  { to: '/scanner', label: 'Scanner', icon: ScanSearch },
  { to: '/history', label: 'Scan history', icon: History },
  { to: '/report', label: 'Report phishing', icon: FileWarning },
  { to: '/profile', label: 'Profile & settings', icon: Settings },
]

export function AppLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const close = () => setMobileOpen(false)
  const handleLogout = async () => { await logout(); navigate('/'); close() }
  return <div className="min-h-screen bg-[#040a12]"><SkipLink/>
    <aside className={`fixed inset-y-0 left-0 z-50 w-72 border-r border-white/5 bg-slate-950 transition-transform ${mobileOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0`}>
      <div className="flex h-full flex-col p-5"><div className="flex items-center justify-between"><Logo/><button className="rounded-lg p-2 text-slate-400 lg:hidden" onClick={close} aria-label="Close menu"><X size={20}/></button></div>
        <div className="mt-7 rounded-2xl border border-sky-400/10 bg-sky-400/5 p-4"><div className="flex items-center gap-2"><Activity size={15} className="text-sky-300"/><span className="text-xs font-semibold text-sky-200">LIVE SCANNER</span></div><p className="mt-2 text-xs leading-5 text-slate-500">URL heuristics, ML, threat intelligence and domain intelligence are combined into one risk assessment.</p></div>
        <nav className="mt-7 flex-1 space-y-1">{items.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} onClick={close} className={({ isActive }) => `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm ${isActive ? 'bg-white/[0.07] text-white' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}><Icon size={18}/>{label}</NavLink>)}
          {user?.role === 'ADMIN' && <><div className="pt-6 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-600">Administration</div><NavLink to="/admin" onClick={close} className={({ isActive }) => `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm ${isActive ? 'bg-white/[0.07] text-white' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}><ShieldCheck size={18}/>Admin center</NavLink></>}
        </nav>
        <div className="border-t border-white/5 pt-4"><div className="mb-3 rounded-xl bg-white/[0.03] p-3"><div className="truncate text-sm font-semibold text-slate-200">{user?.name}</div><div className="truncate text-[11px] text-slate-600">{user?.email}</div></div><Button variant="ghost" onClick={handleLogout} className="w-full justify-start"><LogOut size={18}/>Sign out</Button></div>
      </div>
    </aside>
    {mobileOpen && <button aria-label="Close sidebar" onClick={close} className="fixed inset-0 z-40 bg-black/50 lg:hidden"/>}
    <div className="lg:pl-72"><header className="sticky top-0 z-30 border-b border-white/5 bg-slate-950/80 backdrop-blur-xl"><div className="flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8"><button onClick={() => setMobileOpen(true)} className="rounded-lg p-2 text-slate-300 lg:hidden" aria-label="Open sidebar"><Menu size={21}/></button><div className="hidden lg:block"><span className="text-sm text-slate-500">Security workspace / </span><span className="text-sm text-slate-300">{user?.role === 'ADMIN' ? 'Administration' : 'Overview'}</span></div><div className="flex items-center gap-3"><Badge tone={user?.role === 'ADMIN' ? 'purple' : 'blue'}>{user?.role === 'ADMIN' ? 'ADMIN' : 'SECURE SESSION'}</Badge><div className="grid h-9 w-9 place-items-center rounded-full border border-white/10 bg-white/5 text-xs font-semibold text-white">{user?.name?.split(/\s+/).map((part) => part[0]).join('').slice(0,2).toUpperCase()}</div></div></div></header><main id="main-content" className="min-h-[calc(100vh-4rem)] px-4 py-7 sm:px-6 lg:px-8"><Outlet/></main></div>
  </div>
}
