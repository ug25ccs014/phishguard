import { describe, expect, it } from 'vitest'
import { hasSensitiveQueryParameter, normalizeUrl, sanitizeUrlForStorage, scanInputSchema } from '../src/validators/url.js'

describe('URL security boundary', () => {
  it('rejects non-web protocols', () => {
    expect(() => scanInputSchema.parse({ url: 'file:///etc/passwd' })).toThrow()
    expect(() => scanInputSchema.parse({ url: 'ftp://example.com/file' })).toThrow()
  })

  it('rejects credential-bearing URLs', () => {
    expect(() => scanInputSchema.parse({ url: 'https://user:password@example.com/login' })).toThrow()
  })

  it('strips fragments before persistence', () => {
    expect(normalizeUrl('https://EXAMPLE.com/path#secret-token')).toBe('https://example.com/path')
  })

  it('redacts sensitive query values before persistence/display', () => {
    const value = sanitizeUrlForStorage('https://example.com/reset?token=super-secret&x=1&otp=123456')
    expect(value).toContain('token=%5BREDACTED%5D')
    expect(value).toContain('otp=%5BREDACTED%5D')
    expect(value).toContain('x=1')
    expect(hasSensitiveQueryParameter('https://example.com/?sid=abc')).toBe(true)
  })
})
