import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { getCurrentUser, loginUser, logoutUser, registerUser } from '../services/api'
import type { AuthUser } from '../types'

type AuthContextValue = {
  user: AuthUser | null
  loading: boolean
  login: (input: { email: string; password: string }) => Promise<AuthUser>
  register: (input: { name: string; email: string; password: string }) => Promise<AuthUser>
  logout: () => Promise<void>
  refresh: () => Promise<AuthUser | null>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const current = await getCurrentUser()
      setUser(current)
      return current
    } catch {
      setUser(null)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void refresh() }, [refresh])

  const value = useMemo<AuthContextValue>(() => ({
    user, loading, refresh,
    login: async (input) => { const next = await loginUser(input); setUser(next); return next },
    register: async (input) => { const next = await registerUser(input); setUser(next); return next },
    logout: async () => { await logoutUser(); setUser(null) },
  }), [user, loading, refresh])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}
