export async function fetchWithTimeout(
  input: string | URL,
  init: RequestInit = {},
  timeoutMs = 3500,
): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(input, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

async function readArrayBufferWithLimit(response: Response, maxBytes: number, timeoutMs: number): Promise<ArrayBuffer> {
  const length = Number(response.headers.get('content-length') ?? '0')
  if (Number.isFinite(length) && length > maxBytes) throw new Error('Response exceeded the configured size limit.')

  const bodyPromise = response.arrayBuffer()
  // A successful fetch only means headers arrived; the body can still stall. Keep a hard
  // total body-read deadline and cancel the stream on timeout so providers cannot tie up
  // request resources indefinitely.
  bodyPromise.catch(() => undefined)
  let timer: ReturnType<typeof setTimeout> | null = null
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      void response.body?.cancel().catch(() => undefined)
      reject(new Error('Response body read timed out.'))
    }, timeoutMs)
  })
  try {
    const buffer = await Promise.race([bodyPromise, timeoutPromise])
    if (buffer.byteLength > maxBytes) throw new Error('Response exceeded the configured size limit.')
    return buffer
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export async function readTextWithLimit(response: Response, maxBytes = 2_000_000, timeoutMs = 3500): Promise<string> {
  const buffer = await readArrayBufferWithLimit(response, maxBytes, timeoutMs)
  return new TextDecoder().decode(buffer)
}

export async function readJsonWithLimit<T>(response: Response, maxBytes = 512_000, timeoutMs = 3500): Promise<T> {
  const text = await readTextWithLimit(response, maxBytes, timeoutMs)
  try {
    return JSON.parse(text) as T
  } catch {
    throw new Error('Provider returned invalid JSON.')
  }
}
