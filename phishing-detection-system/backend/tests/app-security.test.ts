import { beforeAll, describe, expect, it } from 'vitest'
import request from 'supertest'
import { readFileSync } from 'node:fs'

let app: typeof import('../src/app.js').app

beforeAll(async () => {
  process.env.NODE_ENV = 'test'
  process.env.DATABASE_URL = process.env.DATABASE_URL ?? 'postgresql://test:test@localhost:5432/phishguard_test'
  process.env.JWT_SECRET = process.env.JWT_SECRET ?? ('test-' + 'x'.repeat(64))
  process.env.CORS_ORIGIN = process.env.CORS_ORIGIN ?? 'http://localhost:5173'
  const mod = await import('../src/app.js')
  app = mod.app
})

describe('Step 5 API security boundary', () => {
  it('exposes liveness with security headers and request id', async () => {
    const response = await request(app).get('/api/v1/live')
    expect(response.status).toBe(200)
    expect(response.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/)
    expect(response.headers['x-content-type-options']).toBe('nosniff')
    expect(response.headers['cache-control']).toContain('no-store')
  })



  it('requires CSRF on login and registration and provides a pre-auth token bootstrap endpoint', () => {
    const routes = readFileSync(new URL('../src/routes/auth.ts', import.meta.url), 'utf8')
    expect(routes).toContain("authRouter.get('/csrf', issueCsrf)")
    expect(routes).toContain("authRouter.post('/register', authAttemptLimit, requireCsrf, register)")
    expect(routes).toContain("authRouter.post('/login', authAttemptLimit, requireCsrf, login)")
  })

  it('allows anonymous scan writes through the conditional CSRF boundary', async () => {
    const authModule = await import('../src/middleware/auth.js')
    const req = { method: 'POST', authUser: undefined, header: () => undefined } as any
    const res = {} as any
    let called = false
    authModule.requireCsrfIfAuthenticated(req, res, () => { called = true })
    expect(called).toBe(true)
  })

  it('denies unapproved browser origins', async () => {
    const response = await request(app).get('/api/v1/live').set('Origin', 'https://attacker.example')
    expect(response.status).toBe(403)
    expect(response.body.error.code).toBe('CORS_ORIGIN_DENIED')
  })

  it('keeps cookie names constrained and production security rules enforced', () => {
    const envSource = readFileSync(new URL('../src/config/env.ts', import.meta.url), 'utf8')
    expect(envSource).toContain("AUTH_COOKIE_NAME: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/)")
    expect(envSource).toContain("value.NODE_ENV === 'production'")
    expect(envSource).toContain("value.AUTH_COOKIE_SECURE !== 'true'")
  })

  it('rejects malformed JSON safely', async () => {
    const response = await request(app).post('/api/v1/scans').set('Content-Type', 'application/json').send('{"url":')
    expect(response.status).toBe(400)
    expect(response.body.error.code).toBe('INVALID_JSON')
  })
})
