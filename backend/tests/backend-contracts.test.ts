import { describe, expect, it } from 'vitest'
import { idParamSchema, reportCreateSchema } from '../src/validators/workspace.js'
import { sanitizeUrlForStorage } from '../src/validators/url.js'
import { canDeleteScan, canReadScan } from '../src/services/authorization.js'
import { getCsrfCookie } from '../src/services/auth.js'
import { verifyPassword, hashPassword } from '../src/services/authCrypto.js'

describe('backend API contracts', () => {
  it('normalizes report URLs and strips fragments before persistence input', () => {
    const result = reportCreateSchema.parse({
      url: 'https://example.com/account#sensitive-fragment',
      category: 'credential',
      description: 'Suspicious login page',
    })
    expect(result.url).toBe('https://example.com/account')
  })

  it('enforces scan ownership semantics before loading another user’s data', () => {
    expect(canReadScan('u1', 'USER', 'u1')).toBe(true)
    expect(canReadScan('u1', 'USER', 'u2')).toBe(false)
    expect(canReadScan('admin', 'ADMIN', 'u2')).toBe(true)
    expect(canDeleteScan('u1', 'u1')).toBe(true)
    expect(canDeleteScan('u1', 'u2')).toBe(false)
  })

  it('rejects malformed route ids before database access', () => {
    expect(() => idParamSchema.parse({ id: '../other-user-scan' })).toThrow()
    expect(() => idParamSchema.parse({ id: 'scan_123' })).not.toThrow()
  })

  it('redacts sensitive URL query values at the storage boundary', () => {
    const result = sanitizeUrlForStorage('https://example.com/reset?token=super-secret&next=1&access_token=abc123')
    expect(result).toContain('token=%5BREDACTED%5D')
    expect(result).toContain('access_token=%5BREDACTED%5D')
    expect(result).toContain('next=1')
  })

  it('rejects unreasonable scrypt parameters instead of spending excessive resources', async () => {
    const hash = await hashPassword('correct-password-2026')
    const parts = hash.split('$')
    parts[1] = '1048576'
    await expect(verifyPassword('correct-password-2026', parts.join('$'))).resolves.toBe(false)
  })
})
