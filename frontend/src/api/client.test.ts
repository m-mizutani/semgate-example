import { afterEach, describe, expect, it, vi } from 'vitest'
import { BlockedError, greet, RequestError } from './client'

function stubFetch(res: Response) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(res))
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('client rate limit handling', () => {
  it('reports the Retry-After seconds on 429', async () => {
    stubFetch(new Response('{"error":"rate limit exceeded"}', { status: 429, headers: { 'Retry-After': '42' } }))
    const err = await greet('Alice').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(RequestError)
    expect((err as RequestError).status).toBe(429)
    expect((err as RequestError).message).toBe('Too many requests. Try again in 42 seconds.')
  })

  it('falls back to a generic message on 429 without Retry-After', async () => {
    stubFetch(new Response('{"error":"rate limit exceeded"}', { status: 429 }))
    const err = await greet('Alice').catch((e: unknown) => e)
    expect((err as RequestError).message).toBe('Too many requests. Try again later.')
  })
})

describe('client guard handling', () => {
  it('reports a guard block as BlockedError with its verdict', async () => {
    stubFetch(
      new Response(
        JSON.stringify({
          blocked: true,
          category: 'ssti',
          probability: 0.93,
          confidence: 0.81,
          message: 'semgate blocked this request before it reached the vulnerable handler',
        }),
        { status: 403 },
      ),
    )
    const err = await greet('{{7*7}}').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(BlockedError)
    const blocked = err as BlockedError
    expect(blocked.status).toBe(403)
    expect(blocked.category).toBe('ssti')
    expect(blocked.probability).toBe(0.93)
    expect(blocked.confidence).toBe(0.81)
  })

  it('reports a 403 that is not a guard block as a plain RequestError', async () => {
    stubFetch(new Response('{"error":"forbidden"}', { status: 403 }))
    const err = await greet('Alice').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(RequestError)
    expect(err).not.toBeInstanceOf(BlockedError)
  })

  it('reports an unavailable guard on 503', async () => {
    stubFetch(
      new Response('{"error":"the guard could not evaluate this request"}', { status: 503 }),
    )
    const err = await greet('Alice').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(RequestError)
    expect((err as RequestError).status).toBe(503)
    expect((err as RequestError).message).toBe('the guard could not evaluate this request')
  })
})
