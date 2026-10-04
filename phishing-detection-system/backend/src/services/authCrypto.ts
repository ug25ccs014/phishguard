import { createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

import type { BinaryLike, ScryptOptions } from 'node:crypto'

const scryptAsync = promisify(scrypt) as unknown as (password: BinaryLike, salt: BinaryLike, keylen: number, options: ScryptOptions) => Promise<Buffer>

export type JwtPayload = {
  sub: string
  sid: string
  role: 'USER' | 'ADMIN'
  email: string
  iat: number
  exp: number
  iss: 'phishguard'
  aud: 'phishguard-web'
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16)
  const derived = await scryptAsync(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }) as Buffer
  return `scrypt$32768$8$1$${salt.toString('base64url')}$${derived.toString('base64url')}`
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [scheme, nRaw, rRaw, pRaw, saltRaw, digestRaw] = encoded.split('$')
  if (scheme !== 'scrypt' || !nRaw || !rRaw || !pRaw || !saltRaw || !digestRaw) return false
  try {
    const n = Number(nRaw)
    const r = Number(rRaw)
    const p = Number(pRaw)
    const salt = Buffer.from(saltRaw, 'base64url')
    const expected = Buffer.from(digestRaw, 'base64url')
    if (!Number.isSafeInteger(n) || n < 16384 || n > 131072 || (n & (n - 1)) !== 0) return false
    if (!Number.isSafeInteger(r) || r < 1 || r > 16) return false
    if (!Number.isSafeInteger(p) || p < 1 || p > 4) return false
    if (salt.length < 16 || salt.length > 64 || expected.length < 32 || expected.length > 128) return false
    const actual = await scryptAsync(password, salt, expected.length, { N: n, r, p, maxmem: 64 * 1024 * 1024 }) as Buffer
    return actual.length === expected.length && timingSafeEqual(actual, expected)
  } catch {
    return false
  }
}

function base64url(value: Buffer | string): string { return Buffer.from(value).toString('base64url') }

export function signAccessToken(input: { sub: string; sid: string; role: 'USER' | 'ADMIN'; email: string; secret: string; ttlMs: number }): string {
  const iat = Math.floor(Date.now() / 1000)
  const exp = Math.floor((Date.now() + input.ttlMs) / 1000)
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const body = base64url(JSON.stringify({ sub: input.sub, sid: input.sid, role: input.role, email: input.email, iat, exp, iss: 'phishguard', aud: 'phishguard-web' }))
  const unsigned = `${header}.${body}`
  return `${unsigned}.${createHmac('sha256', input.secret).update(unsigned).digest('base64url')}`
}

export function verifyAccessToken(token: string, secret: string): JwtPayload | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [header, body, signature] = parts
  try {
    const expected = createHmac('sha256', secret).update(`${header}.${body}`).digest()
    const actual = Buffer.from(signature, 'base64url')
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null
    const parsedHeader = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as { alg?: string; typ?: string }
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as Partial<JwtPayload>
    const now = Math.floor(Date.now() / 1000)
    if (parsedHeader.alg !== 'HS256' || parsedHeader.typ !== 'JWT') return null
    if (payload.iss !== 'phishguard' || payload.aud !== 'phishguard-web') return null
    if (typeof payload.sub !== 'string' || typeof payload.sid !== 'string' || typeof payload.email !== 'string') return null
    if (payload.role !== 'USER' && payload.role !== 'ADMIN') return null
    if (typeof payload.exp !== 'number' || payload.exp <= now) return null
    if (typeof payload.iat !== 'number' || payload.iat > now + 60) return null
    return payload as JwtPayload
  } catch { return null }
}
