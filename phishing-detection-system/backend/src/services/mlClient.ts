import { env } from '../config/env.js'
import { readJsonWithLimit } from './intelligence/http.js'
import { z } from 'zod'

export class MLServiceError extends Error {
  constructor(message: string, public readonly statusCode = 503) {
    super(message)
    this.name = 'MLServiceError'
  }
}

const featureValueSchema = z.number().finite()
const mlResponseSchema = z.object({
  prediction: z.union([z.literal(0), z.literal(1)]),
  label: z.enum(['LEGITIMATE', 'PHISHING']),
  phishingProbability: z.number().finite().min(0).max(1),
  legitimateProbability: z.number().finite().min(0).max(1),
  featureVersion: z.string().min(1).max(100),
  modelVersion: z.string().min(1).max(200),
  modelName: z.string().min(1).max(200),
  features: z.record(z.string().max(100), featureValueSchema).refine((value) => Object.keys(value).length > 0 && Object.keys(value).length <= 128, 'Unexpected feature count.'),
  topModelFeatures: z.array(z.object({
    feature: z.string().min(1).max(100),
    importance: featureValueSchema,
  })).max(16),
  probabilityCalibrated: z.boolean().default(false),
}).superRefine((value, ctx) => {
  if (Math.abs((value.phishingProbability + value.legitimateProbability) - 1) > 0.00001) {
    ctx.addIssue({ code: 'custom', path: ['legitimateProbability'], message: 'Probability values must sum to approximately 1.' })
  }
  const expectedLabel = value.prediction === 1 ? 'PHISHING' : 'LEGITIMATE'
  if (value.label !== expectedLabel) {
    ctx.addIssue({ code: 'custom', path: ['label'], message: 'Prediction label is inconsistent with prediction value.' })
  }
})

export type MLResponse = z.infer<typeof mlResponseSchema>

export async function predictWithML(url: string): Promise<MLResponse> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), env.ML_SERVICE_TIMEOUT_MS)

  try {
    let response: Response
    try {
      response = await fetch(`${env.ML_SERVICE_URL.replace(/\/$/, '')}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ url }),
        redirect: 'error',
        signal: controller.signal,
      })
    } catch (error) {
      const message = error instanceof Error && error.name === 'AbortError'
        ? 'The ML service timed out.'
        : 'The ML service could not be reached.'
      throw new MLServiceError(message)
    }

    const payload = await readJsonWithLimit<unknown>(response, 256_000, env.ML_SERVICE_TIMEOUT_MS).catch(() => null)
    if (!response.ok) {
      const statusCode = response.status >= 500 ? 503 : 422
      const message = statusCode === 503
        ? 'The ML service is temporarily unavailable.'
        : 'The ML service rejected the prediction request.'
      throw new MLServiceError(message, statusCode)
    }

    const parsed = mlResponseSchema.safeParse(payload)
    if (!parsed.success) {
      throw new MLServiceError('The ML service returned an invalid prediction payload.')
    }
    return parsed.data
  } finally {
    clearTimeout(timer)
  }
}
