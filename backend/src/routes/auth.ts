import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { changePassword, issueCsrf, login, logout, me, register, updateProfile } from '../controllers/auth.js'
import { requireAuth, requireCsrf } from '../middleware/auth.js'

export const authRouter = Router()
const authAttemptLimit = rateLimit({ windowMs: 15 * 60_000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: { code: 'AUTH_RATE_LIMITED', message: 'Too many authentication attempts. Try again later.' } } })
authRouter.get('/csrf', issueCsrf)
authRouter.post('/register', authAttemptLimit, requireCsrf, register)
authRouter.post('/login', authAttemptLimit, requireCsrf, login)
authRouter.post('/logout', requireAuth, requireCsrf, logout)
authRouter.get('/me', requireAuth, me)
authRouter.patch('/profile', requireAuth, requireCsrf, updateProfile)
authRouter.patch('/password', requireAuth, requireCsrf, changePassword)
