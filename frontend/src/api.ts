export const API_URL = (import.meta.env.VITE_API_URL || '/api/v1').replace(/\/$/, '')
export const API_CONTRACT_VERSION = '1.0.0'

let bearerToken = ''
const token = () => bearerToken

export const setToken = (value: string) => { bearerToken = value }

export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly code: string, readonly requestId: string | null, readonly details: unknown = null) {
    super(requestId ? `${message} [${requestId}]` : message)
  }
}

type ApiRequestInit = RequestInit & {timeoutMs?: number; retries?: number}

export async function api<T>(path: string, init: ApiRequestInit = {}): Promise<T> {
  const {timeoutMs = 30_000, retries = init.method && init.method !== 'GET' ? 0 : 1, ...requestInit} = init
  let attempt = 0
  while (true) {
    const headers = new Headers(init.headers)
    if (init.body) headers.set('Content-Type', 'application/json')
    if (token()) headers.set('Authorization', `Bearer ${token()}`)
    headers.set('X-Request-ID', globalThis.crypto?.randomUUID?.() || `web-${Date.now()}-${Math.random().toString(16).slice(2)}`)
    const controller = new AbortController()
    let timedOut = false
    const timeout = window.setTimeout(() => { timedOut = true; controller.abort() }, timeoutMs)
    const externalSignal = init.signal
    const abort = () => controller.abort()
    externalSignal?.addEventListener('abort', abort, {once: true})
    try {
      const broker=window.secureAgent?.backendRequest
      const response = broker ? await new Promise((resolve: (value: {status:number;headers:{requestId:string|null;contractVersion:string|null};body:string}) => void, reject: (reason: Error) => void) => {
        // ipcRenderer.invoke() cannot be aborted from the renderer, so the
        // timeout and cancel semantics are enforced by racing the broker
        // request against controller.signal (fired by the timeoutMs timer
        // above and by the external signal). The catch block maps the
        // rejection to REQUEST_TIMEOUT / REQUEST_CANCELLED respectively.
        const onAbort = () => reject(new DOMException('Aborted', 'AbortError'))
        if (controller.signal.aborted) { onAbort(); return }
        controller.signal.addEventListener('abort', onAbort, {once: true})
        broker({path:API_URL+path,method:requestInit.method||'GET',body:typeof requestInit.body==='string'?requestInit.body:undefined}).then(
          (value) => { controller.signal.removeEventListener('abort', onAbort); resolve(value) },
          (reason) => { controller.signal.removeEventListener('abort', onAbort); reject(reason instanceof Error ? reason : new Error(String(reason))) },
        )
      }).then((r)=>new Response(r.body,{status:r.status,headers:{'x-request-id':r.headers.requestId||'','x-api-contract-version':r.headers.contractVersion||''}})) : await fetch(API_URL + path, {...requestInit, headers, credentials: 'same-origin', signal: controller.signal})
      const requestId = response.headers.get('x-request-id')
      const contractVersion = response.headers.get('x-api-contract-version')
      if (contractVersion && contractVersion !== API_CONTRACT_VERSION) throw new ApiError(`Unsupported API contract ${contractVersion}`, 0, 'API_CONTRACT_MISMATCH', requestId)
      if (!response.ok) {
        const data: unknown = await response.json().catch(() => ({detail: response.statusText}))
        const payload = typeof data === 'object' && data !== null && 'error' in data && typeof data.error === 'object' && data.error !== null ? data.error : typeof data === 'object' && data !== null && 'detail' in data && typeof data.detail === 'object' && data.detail !== null ? data.detail : data
        const code = typeof payload === 'object' && payload !== null && 'code' in payload ? String(payload.code) : `HTTP_${response.status}`
        const message = typeof payload === 'object' && payload !== null && 'message' in payload ? String(payload.message) : typeof payload === 'object' && payload !== null && 'detail' in payload ? String(payload.detail) : response.statusText || 'Request failed'
        const details = typeof payload === 'object' && payload !== null && 'details' in payload ? payload.details : null
        const bodyRequestId = typeof data === 'object' && data !== null && 'request_id' in data ? String(data.request_id) : null
        throw new ApiError(`${code}: ${message}`, response.status, code, requestId || bodyRequestId, details)
      }
      if (response.status === 204) return undefined as T
      try { return await response.json() as T }
      catch { throw new ApiError('Backend returned malformed JSON', response.status, 'MALFORMED_RESPONSE', requestId) }
    } catch (reason: unknown) {
      if (reason instanceof ApiError) {
        if (attempt < retries && (reason.status === 429 || reason.status >= 500)) { attempt += 1; await new Promise((resolve) => window.setTimeout(resolve, 350 * attempt)); continue }
        throw reason
      }
      if (externalSignal?.aborted) throw new ApiError('Request was cancelled', 0, 'REQUEST_CANCELLED', null)
      if (timedOut) throw new ApiError('Request timed out', 0, 'REQUEST_TIMEOUT', null)
      if (attempt < retries) { attempt += 1; await new Promise((resolve) => window.setTimeout(resolve, 350 * attempt)); continue }
      throw new ApiError('Backend is unavailable', 0, 'BACKEND_UNAVAILABLE', null, reason instanceof Error ? reason.message : null)
    } finally {
      window.clearTimeout(timeout)
      externalSignal?.removeEventListener('abort', abort)
    }
  }
}

export async function publicHealth(): Promise<{status: string; version: string}> {
  return api<{status: string; version: string}>('/health')
}
