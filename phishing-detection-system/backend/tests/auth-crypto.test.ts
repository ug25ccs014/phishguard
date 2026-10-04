import { describe, expect, it } from 'vitest'
import { hashPassword, signAccessToken, verifyAccessToken, verifyPassword } from '../src/services/authCrypto.js'

describe('authentication cryptography', () => {
  const signingKey = 'test-secret-'.padEnd(40, 'x')

  it('hashes and verifies passwords without storing the plaintext', async () => {
    const pwd = 'Correct-Horse-Battery-Staple-2026'
    const hash = await hashPassword(pwd)
    expect(hash).toMatch(/^scrypt\$/)
    expect(hash).not.toContain(pwd)
    await expect(verifyPassword(pwd, hash)).resolves.toBe(true)
    await expect(verifyPassword('incorrect-password', hash)).resolves.toBe(false)
  })

  it('rejects expired JWTs', () => {
    const token = signAccessToken({ sub: 'user-1', sid: 'session-1', role: 'USER', email: 'user@example.com', secret: signingKey, ttlMs: -1 })
    expect(verifyAccessToken(token, signingKey)).toBeNull()
  })

  it('signs and verifies JWT sessions and rejects tampering', async () => {
    const token = signAccessToken({ sub: 'user-1', sid: 'session-1', role: 'USER', email: 'user@example.com', secret: signingKey, ttlMs: 60_000 })
    const payload = verifyAccessToken(token, signingKey)
    expect(payload?.sub).toBe('user-1')
    expect(payload?.sid).toBe('session-1')
    const tampered = `${token.slice(0, -1)}${token.endsWith('a') ? 'b' : 'a'}`
    expect(verifyAccessToken(tampered, signingKey)).toBeNull()
  })
})
