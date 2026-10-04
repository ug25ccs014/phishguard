import { LoaderCircle } from 'lucide-react'
import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export function ProtectedRoute({ role }: { role?: 'USER' | 'ADMIN' }) {
  const { user, loading } = useAuth()
  const location = useLocation()
  if (loading) return <div className="grid min-h-[60vh] place-items-center text-slate-400"><div className="flex items-center gap-3"><LoaderCircle className="animate-spin text-sky-300" size={20}/> Loading secure workspace…</div></div>
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  if (role && user.role !== role) return <Navigate to="/dashboard" replace />
  return <Outlet />
}
