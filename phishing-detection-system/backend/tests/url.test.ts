import { describe, expect, it } from 'vitest'
import { normalizeUrl } from '../src/validators/url.js'

describe('URL foundation', () => {
  it('normalizes a URL by removing its fragment', () => {
    expect(normalizeUrl('https://Example.com/path#tracking')).toBe('https://example.com/path')
  })
})
