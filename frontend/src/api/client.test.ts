import { afterEach, describe, expect, it, vi } from 'vitest'
import { greet, RequestError } from './client'

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
