import type { AuthUser } from '../services/auth.js'

declare global {
  namespace Express {
    interface Request {
      authUser?: AuthUser
      requestId?: string
    }
  }
}

export {}
