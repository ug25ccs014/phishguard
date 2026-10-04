import { Router } from 'express'
import { adminModelInfo, adminOverview, adminProviderStatus, adminReports, createReport, dashboard, deleteScan, getScan, listMyReports, listScans, updateAdminReport } from '../controllers/workspace.js'
import { requireAuth, requireCsrf, requireRole } from '../middleware/auth.js'
import { adminWriteRateLimit, reportRateLimit } from '../middleware/rateLimits.js'

export const workspaceRouter = Router()
workspaceRouter.get('/dashboard', requireAuth, dashboard)
workspaceRouter.get('/scans', requireAuth, listScans)
workspaceRouter.get('/scans/:id', requireAuth, getScan)
workspaceRouter.delete('/scans/:id', requireAuth, requireCsrf, deleteScan)
workspaceRouter.post('/reports', reportRateLimit, requireAuth, requireCsrf, createReport)
workspaceRouter.get('/reports', requireAuth, listMyReports)

workspaceRouter.get('/admin/overview', requireAuth, requireRole('ADMIN'), adminOverview)
workspaceRouter.get('/admin/reports', requireAuth, requireRole('ADMIN'), adminReports)
workspaceRouter.patch('/admin/reports/:id', adminWriteRateLimit, requireAuth, requireRole('ADMIN'), requireCsrf, updateAdminReport)
workspaceRouter.get('/admin/providers', requireAuth, requireRole('ADMIN'), adminProviderStatus)
workspaceRouter.get('/admin/model', requireAuth, requireRole('ADMIN'), adminModelInfo)
