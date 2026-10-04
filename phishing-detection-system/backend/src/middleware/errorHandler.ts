import type { ErrorRequestHandler } from 'express'
import { ZodError } from 'zod'
import { logger } from '../utils/logger.js'

function isBodyParserSyntaxError(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'type' in error && (error as { type?: unknown }).type === 'entity.parse.failed')
}

export const errorHandler: ErrorRequestHandler = (error, req, res, _next) => {
  if (isBodyParserSyntaxError(error)) {
    return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'The request body contains invalid JSON.' } })
  }

  if (error instanceof ZodError) {
    return res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed.',
        details: error.issues.map((issue) => ({
          path: issue.path.join('.'),
          code: issue.code,
          message: issue.message,
        })),
      },
    })
  }

  logger.error('Unhandled request error', {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    error: error instanceof Error ? error.message : String(error),
  })
  return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected server error occurred.' } })
}
