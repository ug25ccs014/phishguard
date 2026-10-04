import { describe, expect, it } from 'vitest'
import { safeInternalDestination } from './navigation'

describe('safe internal destinations', () => {
  it('accepts local paths and rejects external/protocol-relative destinations', () => {
    expect(safeInternalDestination('/dashboard')).toBe('/dashboard')
    expect(safeInternalDestination('/history?page=2')).toBe('/history?page=2')
    expect(safeInternalDestination('https://evil.example')).toBe('/dashboard')
    expect(safeInternalDestination('//evil.example')).toBe('/dashboard')
    expect(safeInternalDestination('javascript:alert(1)')).toBe('/dashboard')
    expect(safeInternalDestination('/\\evil.example')).toBe('/dashboard')
  })
})
