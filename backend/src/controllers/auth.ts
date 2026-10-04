import type { RequestHandler } from 'express'
import { Prisma } from '@prisma/client'
import { prisma } from '../lib/prisma.js'
import { createUserSession, destroyCurrentSession, hashPassword, verifyPassword, type AuthUser, getAuthenticatedUser, issueCsrfCookie } from '../services/auth.js'
import { loginSchema, passwordChangeSchema, profileSchema, registerSchema } from '../validators/auth.js'

export const issueCsrf: RequestHandler = async (_req, res) => {
  const token = issueCsrfCookie(res)
  return res.json({ csrfToken: token })
}

function publicUser(user: AuthUser) {
  return { id: user.id, email: user.email, name: user.name, role: user.role, highRiskAlerts: user.highRiskAlerts, weeklySummary: user.weeklySummary }
}

export const register: RequestHandler = async (req, res, next) => {
  try {
    const input = registerSchema.parse(req.body)
    const existing = await prisma.user.findUnique({ where: { email: input.email }, select: { id: true } })
    if (existing) return res.status(409).json({ error: { code: 'EMAIL_IN_USE', message: 'An account with this email already exists.' } })
    const userRecord = await prisma.user.create({
      data: { email: input.email, name: input.name, passwordHash: await hashPassword(input.password) },
    })
    const user: AuthUser = { id: userRecord.id, email: userRecord.email, name: userRecord.name, role: userRecord.role, highRiskAlerts: userRecord.highRiskAlerts, weeklySummary: userRecord.weeklySummary }
    await createUserSession(user, req, res)
    return res.status(201).json({ user: publicUser(user) })
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') return res.status(409).json({ error: { code: 'EMAIL_IN_USE', message: 'An account with this email already exists.' } })
    return next(error)
  }
}

export const login: RequestHandler = async (req, res, next) => {
  try {
    const input = loginSchema.parse(req.body)
    const record = await prisma.user.findUnique({ where: { email: input.email } })
    if (!record || !await verifyPassword(input.password, record.passwordHash)) return res.status(401).json({ error: { code: 'INVALID_CREDENTIALS', message: 'Email or password is incorrect.' } })
    const user: AuthUser = { id: record.id, email: record.email, name: record.name, role: record.role, highRiskAlerts: record.highRiskAlerts, weeklySummary: record.weeklySummary }
    await createUserSession(user, req, res)
    return res.json({ user: publicUser(user) })
  } catch (error) { return next(error) }
}

export const logout: RequestHandler = async (req, res, next) => {
  try { await destroyCurrentSession(req, res); return res.status(204).send() } catch (error) { return next(error) }
}

export const me: RequestHandler = async (req, res) => {
  const user = req.authUser ?? await getAuthenticatedUser(req)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication is required.' } })
  return res.json({ user: publicUser(user) })
}

export const updateProfile: RequestHandler = async (req, res, next) => {
  try {
    const input = profileSchema.parse(req.body)
    const updated = await prisma.user.update({ where: { id: req.authUser!.id }, data: input })
    req.authUser = { ...req.authUser!, name: updated.name, highRiskAlerts: updated.highRiskAlerts, weeklySummary: updated.weeklySummary }
    return res.json({ user: publicUser(req.authUser) })
  } catch (error) { return next(error) }
}

export const changePassword: RequestHandler = async (req, res, next) => {
  try {
    const input = passwordChangeSchema.parse(req.body)
    const record = await prisma.user.findUnique({ where: { id: req.authUser!.id } })
    if (!record || !await verifyPassword(input.currentPassword, record.passwordHash)) return res.status(400).json({ error: { code: 'CURRENT_PASSWORD_INVALID', message: 'Current password is incorrect.' } })
    if (await verifyPassword(input.newPassword, record.passwordHash)) return res.status(400).json({ error: { code: 'PASSWORD_REUSE', message: 'Choose a new password that differs from the current password.' } })
    await prisma.$transaction([
      prisma.user.update({ where: { id: record.id }, data: { passwordHash: await hashPassword(input.newPassword), passwordChangedAt: new Date() } }),
      prisma.authSession.updateMany({ where: { userId: record.id, revokedAt: null }, data: { revokedAt: new Date() } }),
    ])
    return res.status(204).send()
  } catch (error) { return next(error) }
}
