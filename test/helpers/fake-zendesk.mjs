import assert from 'node:assert/strict'

function parseAuthorizationScheme(value) {
  if (typeof value !== 'string') return undefined
  const separator = value.indexOf(' ')
  return separator === -1 ? value : value.slice(0, separator)
}

function headersFrom(input, init) {
  const headers = new Headers(input instanceof Request ? input.headers : undefined)
  for (const [name, value] of new Headers(init?.headers)) headers.set(name, value)
  return headers
}

async function bodyFrom(input, init) {
  if (init?.body !== undefined && init.body !== null) return String(init.body)
  if (input instanceof Request) return input.clone().text()
  return ''
}

export function createFakeZendesk() {
  const requests = []
  const queued = []

  const fetch = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : input)
    const method = (init.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase()
    const headers = headersFrom(input, init)
    const body = await bodyFrom(input, init)
    const contentType = headers.get('content-type') ?? ''
    const request = {
      method,
      url: url.href,
      pathname: url.pathname,
      json: contentType.includes('application/json') && body ? JSON.parse(body) : undefined,
      form: contentType.includes('application/x-www-form-urlencoded') && body
        ? Object.fromEntries(new URLSearchParams(body))
        : undefined,
      authorizationScheme: parseAuthorizationScheme(headers.get('authorization')),
      redirect: init.redirect,
    }
    requests.push(request)

    const next = queued.shift()
    assert.ok(next, `unexpected ${method} ${url.pathname}`)
    if (next.kind === 'hung') {
      return new Promise((_resolve, reject) => {
        const abort = () => {
          next.aborted = true
          reject(init.signal?.reason ?? new DOMException('Aborted', 'AbortError'))
        }
        if (init.signal?.aborted) abort()
        else init.signal?.addEventListener('abort', abort, { once: true })
      })
    }
    if (next.kind === 'error') throw next.error
    if (next.kind === 'hung-body') {
      const stream = new ReadableStream({
        start(controller) {
          const abort = () => {
            next.aborted = true
            controller.error(init.signal?.reason ?? new DOMException('Aborted', 'AbortError'))
          }
          if (init.signal?.aborted) abort()
          else init.signal?.addEventListener('abort', abort, { once: true })
        },
      })
      return new Response(stream, {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }

    const responseBody = next.body === undefined
      ? null
      : typeof next.body === 'string'
        ? next.body
        : JSON.stringify(next.body)
    const headersOut = new Headers(next.headers)
    if (responseBody !== null && !headersOut.has('content-type')) {
      headersOut.set('content-type', 'application/json')
    }
    return new Response(next.status === 204 ? null : responseBody, {
      status: next.status,
      headers: headersOut,
    })
  }

  return {
    fetch,
    requests,
    queueResponse({ status = 200, body, headers } = {}) {
      queued.push({ kind: 'response', status, body, headers })
    },
    queueHung() {
      const request = { kind: 'hung', aborted: false }
      queued.push(request)
      return request
    },
    queueHungBody() {
      const request = { kind: 'hung-body', aborted: false }
      queued.push(request)
      return request
    },
    queueError(error) {
      queued.push({ kind: 'error', error })
    },
    assertDrained() {
      assert.equal(queued.length, 0)
    },
  }
}
