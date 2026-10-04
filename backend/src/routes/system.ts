import { Router } from 'express'
import { health, live, meta, ready } from '../controllers/system.js'

export const systemRouter = Router()
systemRouter.get('/health', health)
systemRouter.get('/live', live)
systemRouter.get('/ready', ready)
systemRouter.get('/meta', meta)
