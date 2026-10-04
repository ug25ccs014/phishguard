import type { RequestHandler } from 'express'
import { timingSafeEqual } from 'node:crypto'
import { clearAuthCookies, getAuthenticatedUser, getCsrfCookie } from '../services/auth.js'

export const optionalAuth: RequestHandler = async (req, res, next) => {
  try {
    req.authUser = await getAuthenticatedUser(req) ?? undefined
    if (!req.authUser && req.headers.cookie) clearAuthCookies(res)
    return next()
  } catch (error) { return next(error) }
}

export const requireAuth: RequestHandler = async (req, res, next) => {
  try {
    const user = await getAuthenticatedUser(req)
    if (!user) { clearAuthCookies(res); return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication is required.' } }) }
    req.authUser = user
    return next()
  } catch (error) { return next(error) }
}

export function requireRole(role: 'USER' | 'ADMIN'): RequestHandler {
  return (req, res, next) => {
    if (!req.authUser) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication is required.' } })
    if (req.authUser.role !== role) return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'You do not have permission to access this resource.' } })
    return next()
  }
}

function validateCsrf(req: Parameters<RequestHandler>[0], res: Parameters<RequestHandler>[1], next: Parameters<RequestHandler>[2]) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next()
  const cookieToken = getCsrfCookie(req)
  const headerToken = req.header('x-csrf-token')
  if (!cookieToken || !headerToken) return res.status(403).json({ error: { code: 'CSRF_REQUIRED', message: 'A valid CSRF token is required for this action.' } })
  const a = Buffer.from(cookieToken); const b = Buffer.from(headerToken)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return res.status(403).json({ error: { code: 'CSRF_INVALID', message: 'The CSRF token is invalid.' } })
  return next()
}

export const requireCsrf: RequestHandler = validateCsrf

export const requireCsrfIfAuthenticated: RequestHandler = (req, res, next) => {
  if (!req.authUser) return next()
  return validateCsrf(req, res, next)
}
