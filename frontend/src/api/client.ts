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

async function parse(res: Response): Promise<Envelope> {
  if (res.status === 413) {
    throw new RequestError(413, 'Input is too large (the range accepts at most 1KB).')
  }
  if (res.status === 400) {
    const body = (await res.json().catch(() => ({}))) as { error?: string }
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
