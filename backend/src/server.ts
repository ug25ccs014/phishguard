import { app } from './app.js'
import { env } from './config/env.js'
import { prisma } from './lib/prisma.js'
import { logger } from './utils/logger.js'

const server = app.listen(env.PORT, env.HOST, () => {
  logger.info('PhishGuard backend started', { host: env.HOST, port: env.PORT, stage: 'final-release', version: env.APP_VERSION })
})

let shuttingDown = false
async function shutdown(signal: string) {
  if (shuttingDown) return
  shuttingDown = true
  logger.info('Graceful shutdown started', { signal })
  server.close(async () => {
    await prisma.$disconnect().catch(() => undefined)
    logger.info('Graceful shutdown complete')
    process.exit(0)
  })
  setTimeout(() => process.exit(1), 10_000).unref()
}

process.on('SIGTERM', () => void shutdown('SIGTERM'))
process.on('SIGINT', () => void shutdown('SIGINT'))
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message })
  void shutdown('uncaughtException')
})
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection', { error: reason instanceof Error ? reason.message : String(reason) })
  void shutdown('unhandledRejection')
})
