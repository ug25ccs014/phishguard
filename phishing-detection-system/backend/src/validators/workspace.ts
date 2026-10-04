import { z } from 'zod'
import { ReportStatus } from '@prisma/client'
import { sanitizeUrlForStorage } from './url.js'

const verdictValues = ['LOW RISK','SUSPICIOUS','HIGH RISK','LIKELY PHISHING','KNOWN MALICIOUS'] as const
const reportCategories = ['credential','payment','impersonation','malware','qr-phishing','other'] as const

export const scanQuerySchema = z.object({
  search: z.string().trim().max(160).optional(),
  verdict: z.enum(verdictValues).optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(5).max(50).default(20),
})

export const reportCreateSchema = z.object({
  url: z.string().trim().min(1).max(4096),
  category: z.enum(reportCategories),
  description: z.string().trim().max(2000).optional(),
}).superRefine((value, ctx) => {
  try {
    const u = new URL(value.url)
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw new Error('invalid')
  } catch { ctx.addIssue({ code: 'custom', path: ['url'], message: 'A valid HTTP/HTTPS URL is required.' }) }
}).transform((value) => {
  const u = new URL(value.url)
  u.hash = ''
  return { ...value, url: sanitizeUrlForStorage(u.toString()) }
})

export const reportStatusSchema = z.object({
  status: z.nativeEnum(ReportStatus),
  reviewNote: z.string().trim().max(2000).optional(),
})

export const adminReportsQuerySchema = z.object({
  status: z.nativeEnum(ReportStatus).optional(),
  search: z.string().trim().max(160).optional(),
})
