import type { Request, Response } from 'express'
import { randomBytes } from 'node:crypto'
import { prisma } from '../lib/prisma.js'
import { env } from '../config/env.js'
import { hashPassword, verifyPassword, signAccessToken, verifyAccessToken, type JwtPayload } from './authCrypto.js'

export type AuthUser = {
  id: string
  email: string
  name: string
  role: 'USER' | 'ADMIN'
  highRiskAlerts: boolean
  weeklySummary: boolean
}

const AUTH_COOKIE = env.AUTH_COOKIE_NAME
const CSRF_COOKIE = env.CSRF_COOKIE_NAME
const SESSION_TTL_MS = env.AUTH_SESSION_TTL_HOURS * 60 * 60 * 1000

function parseCookie(header: string | undefined, name: string): string | null {
  if (!header) return null
  const item = header.split(';').map((part) => part.trim()).find((part) => {
    const separator = part.indexOf('=')
    return separator > 0 && part.slice(0, separator) === name
  })
  if (!item) return null
  const separator = item.indexOf('=')
  try { return decodeURIComponent(item.slice(separator + 1)) } catch { return null }
}

function secureCookie(): boolean {
  return env.AUTH_COOKIE_SECURE ? env.AUTH_COOKIE_SECURE === 'true' : env.NODE_ENV === 'production' || env.AUTH_COOKIE_SAMESITE === 'none'
}

function cookieOptions(httpOnly: boolean) {
  return {
    httpOnly,
    secure: secureCookie(),
    sameSite: env.AUTH_COOKIE_SAMESITE as 'lax' | 'strict' | 'none',
    domain: env.COOKIE_DOMAIN || undefined,
    path: '/',
    maxAge: SESSION_TTL_MS,
  }
}

function setCsrfCookie(res: Response, token = randomCsrfToken()): string {
  res.cookie(CSRF_COOKIE, token, { ...cookieOptions(false), httpOnly: false })
  return token
}

function randomCsrfToken(): string { return randomBytes(32).toString('hex') }

export function issueCsrfCookie(res: Response): string { return setCsrfCookie(res) }

export function clearAuthCookies(res: Response): void {
  const opts = { secure: secureCookie(), sameSite: env.AUTH_COOKIE_SAMESITE as 'lax' | 'strict' | 'none', domain: env.COOKIE_DOMAIN || undefined, path: '/' } as const
  res.clearCookie(AUTH_COOKIE, opts)
  res.clearCookie(CSRF_COOKIE, opts)
}

export async function createUserSession(user: AuthUser, req: Request, res: Response): Promise<void> {
  await prisma.authSession.deleteMany({ where: { userId: user.id, OR: [{ expiresAt: { lt: new Date() } }, { revokedAt: { not: null } }] } })
  const session = await prisma.authSession.create({ data: { userId: user.id, expiresAt: new Date(Date.now() + SESSION_TTL_MS), userAgent: String(req.headers['user-agent'] ?? '').slice(0, 400) || null } })
  const token = signAccessToken({ sub: user.id, sid: session.id, role: user.role, email: user.email, secret: env.JWT_SECRET, ttlMs: SESSION_TTL_MS })
  res.cookie(AUTH_COOKIE, token, cookieOptions(true))
  setCsrfCookie(res)
}

export async function destroyCurrentSession(req: Request, res: Response): Promise<void> {
  const token = parseCookie(req.headers.cookie, AUTH_COOKIE)
  const payload = token ? verifyAccessToken(token, env.JWT_SECRET) : null
  if (payload?.sid) await prisma.authSession.updateMany({ where: { id: payload.sid, revokedAt: null }, data: { revokedAt: new Date() } })
  clearAuthCookies(res)
}

export async function getAuthenticatedUser(req: Request): Promise<AuthUser | null> {
  const token = parseCookie(req.headers.cookie, AUTH_COOKIE)
  if (!token) return null
  const payload: JwtPayload | null = verifyAccessToken(token, env.JWT_SECRET)
  if (!payload) return null
  const session = await prisma.authSession.findFirst({
    where: { id: payload.sid, userId: payload.sub, revokedAt: null, expiresAt: { gt: new Date() } },
    include: {
      user: {
        select: { id: true, email: true, name: true, role: true, highRiskAlerts: true, weeklySummary: true },
      },
    },
  })
  if (!session || session.user.role !== payload.role || session.user.email !== payload.email) return null
  const now = Date.now()
  if (!session.lastUsedAt || now - session.lastUsedAt.getTime() > 60_000) {
    await prisma.authSession.update({ where: { id: session.id }, data: { lastUsedAt: new Date(now) } }).catch(() => undefined)
  }
  return { id: session.user.id, email: session.user.email, name: session.user.name, role: session.user.role, highRiskAlerts: session.user.highRiskAlerts, weeklySummary: session.user.weeklySummary }
}

export function getCsrfCookie(req: Request): string | null { return parseCookie(req.headers.cookie, CSRF_COOKIE) }
export { hashPassword, verifyPassword }
