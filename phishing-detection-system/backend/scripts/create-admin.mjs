import { PrismaClient } from '@prisma/client'
import { randomBytes, scrypt } from 'node:crypto'
import { promisify } from 'node:util'

const [emailArg, nameArg] = process.argv.slice(2)
if (!emailArg || !nameArg || process.argv.length !== 4) {
  console.error('Usage: node scripts/create-admin.mjs <email> <name>')
  console.error('Supply PHISHGUARD_ADMIN_PASSWORD through the environment. Do not pass passwords as command-line arguments.')
  process.exit(1)
}

const password = process.env.PHISHGUARD_ADMIN_PASSWORD ?? ''
if (!password) {
  console.error('PHISHGUARD_ADMIN_PASSWORD is required.')
  process.exit(1)
}
if (password.length < 10 || password.length > 128) {
  console.error('Password must be between 10 and 128 characters.')
  process.exit(1)
}

const email = emailArg.trim().toLowerCase()
const name = nameArg.trim()
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { console.error('A valid email address is required.'); process.exit(1) }
if (name.length < 2 || name.length > 80) { console.error('Name must be between 2 and 80 characters.'); process.exit(1) }

const scryptAsync = promisify(scrypt)
const prisma = new PrismaClient()
try {
  const salt = randomBytes(16)
  const digest = await scryptAsync(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })
  const passwordHash = `scrypt$32768$8$1$${salt.toString('base64url')}$${Buffer.from(digest).toString('base64url')}`
  const user = await prisma.$transaction(async (tx) => {
    const user = await tx.user.upsert({ where: { email }, update: { name, passwordHash, role: 'ADMIN', passwordChangedAt: new Date() }, create: { email, name, passwordHash, role: 'ADMIN' } })
    await tx.authSession.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } })
    return user
  })
  console.log(`Admin account ready: ${user.email}`)
} finally { await prisma.$disconnect() }
