// Thin client over the /api endpoints. Every endpoint returns the same
// envelope; the result field is endpoint-specific.

export interface Envelope {
  endpoint: string
  exploited: boolean
  category: string
  rule_id: string
  detail: string
  message: string
  result: Record<string, unknown>
}

export class RequestError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

// blockBody is the 403 body the semgate guard writes instead of forwarding the
// request to the vulnerable handler.
interface BlockBody {
  blocked: boolean
  category: string
  probability: number
  confidence: number
  message: string
}

// BlockedError marks the one failure that is not the range refusing bad input:
// the guard judged the request to be an attack and stopped it. Callers tell it
// apart with `err instanceof BlockedError`, not by the status code.
export class BlockedError extends RequestError {
  readonly category: string
  readonly probability: number
  readonly confidence: number
  constructor(body: BlockBody) {
    super(403, body.message)
    this.category = body.category
    this.probability = body.probability
    this.confidence = body.confidence
  }
}

async function readJSON<T>(res: Response): Promise<Partial<T>> {
  return (await res.json().catch(() => ({}))) as Partial<T>
}

async function parse(res: Response): Promise<Envelope> {
  if (res.status === 403) {
    const body = await readJSON<BlockBody>(res)
    if (body.blocked) {
      throw new BlockedError({
        blocked: true,
        category: body.category ?? 'unknown',
        probability: body.probability ?? 0,
        confidence: body.confidence ?? 0,
        message: body.message ?? 'semgate blocked this request before it reached the handler.',
      })
    }
    throw new RequestError(403, body.message ?? 'Forbidden.')
  }
  if (res.status === 503) {
    const body = await readJSON<{ error: string }>(res)
    throw new RequestError(503, body.error ?? 'The guard could not evaluate this request.')
  }
  if (res.status === 413) {
    throw new RequestError(413, 'Input is too large (the range accepts at most 1KB).')
  }
  if (res.status === 429) {
    const retryAfter = res.headers.get('Retry-After')
    throw new RequestError(
      429,
      retryAfter
        ? `Too many requests. Try again in ${retryAfter} seconds.`
        : 'Too many requests. Try again later.',
    )
  }
  if (res.status === 400) {
    const body = await readJSON<{ error: string }>(res)
    throw new RequestError(400, body.error ?? 'Bad request.')
  }
  if (!res.ok) {
    throw new RequestError(res.status, `Unexpected status ${res.status}.`)
  }
  return (await res.json()) as Envelope
}

export async function login(username: string, password: string): Promise<Envelope> {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  return parse(res)
}

async function getQuery(path: string, param: string, value: string): Promise<Envelope> {
  const res = await fetch(`${path}?${param}=${encodeURIComponent(value)}`)
  return parse(res)
}

export const ping = (host: string) => getQuery('/api/ping', 'host', host)
export const files = (path: string) => getQuery('/api/files', 'path', path)
export const greet = (name: string) => getQuery('/api/greet', 'name', name)
export const fetchUrl = (url: string) => getQuery('/api/fetch', 'url', url)

export async function track(logTag: string): Promise<Envelope> {
  const res = await fetch('/api/track', { headers: { 'X-Log-Tag': logTag } })
  return parse(res)
}
