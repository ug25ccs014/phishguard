import type { RequestHandler } from 'express'
import { scanInputSchema } from '../validators/url.js'
import { scanUrl } from '../services/scanService.js'
import { MLServiceError } from '../services/mlClient.js'

export const createScan: RequestHandler = async (req, res, next) => {
  try {
    const input = scanInputSchema.parse(req.body)
    const assessment = await scanUrl(input.url, req.authUser?.id)
    return res.status(200).json(assessment)
  } catch (error) {
    if (error instanceof MLServiceError) return res.status(error.statusCode).json({ error: { code: 'ML_SERVICE_UNAVAILABLE', message: error.message } })
    return next(error)
  }
}
