import type { InternalAxiosRequestConfig } from 'axios'

// authenticationContext.ts holds the browser's current authentication generation and
// the central session's CSRF material in memory. API interceptors and the session
// store share this small transport boundary without importing each other. The opaque
// authentication cookie stays inaccessible to JavaScript, and central credentials are
// never written to browser storage by this module.
//
// Each explicit session replacement advances the generation before publishing new
// credentials. Requests capture it when dispatched and discard results after a later
// replacement, preventing an earlier profile or unauthorized response from changing a
// newer login. Expiration notifies subscribers only after clearing the captured central
// context; repeated or stale expiration attempts cannot clear a replacement session.

// CentralTransport contains the anti-CSRF proof and absolute local session deadline.
// Neither value authenticates a request without the server-owned HttpOnly cookie.
export interface CentralTransport {
  csrfToken: string // Session anti-CSRF proof.
  expiresAt: number // Absolute expiry milliseconds.
}

// AuthenticationRequest records the session ownership captured by the request interceptor.
export interface AuthenticationRequest extends InternalAxiosRequestConfig {
  _authenticationEpoch?: number // Dispatch session generation.
  _centralAuthentication?: boolean // Cookie-only recovery policy.
  allowLegacyIdentityBinding?: boolean // Explicit legacy binding proof.
}

// The module owns one current transport snapshot and generation. Subscribers observe
// expiration only, leaving explicit adoption and normal logout under store control.
let epoch = 0 // Current authentication generation.
let central: Readonly<CentralTransport> | null = null // Active cookie transport context.
const expirationListeners = new Set<(expiredEpoch: number) => void>() // Store expiration subscriptions.

// authenticationEpoch returns the generation used to fence in-flight authentication work.
export function authenticationEpoch(): number {
  return epoch
}

// centralTransport exposes the immutable current cookie context, or null when absent.
export function centralTransport(): Readonly<CentralTransport> | null {
  return central
}

// authenticationHeaders selects the current cookie proof or legacy bearer at dispatch.
// Cookie-only entry requests never borrow stored credentials. Sending the CSRF proof
// on reads also lets the backend reject a cookie replaced by another browser tab.
export function authenticationHeaders(cookieOnly = false): Record<string, string> {
  if (central) return { 'X-CSRF-Token': central.csrfToken }
  if (cookieOnly) return {}
  const token = localStorage.getItem('auth_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

// replaceAuthentication advances session ownership and installs the selected transport.
// Call it before publishing a different browser identity. Null selects legacy or
// anonymous transport, without reading or writing any persistent credentials.
export function replaceAuthentication(value: CentralTransport | null = null): number {
  epoch += 1
  central = value === null ? null : Object.freeze({ ...value })
  return epoch
}

// assertAuthenticationEpoch rejects results belonging to a superseded browser session.
// Callers capture the epoch before asynchronous work and check it before publication.
// The stable error code lets views discard stale work without interpreting server text.
export function assertAuthenticationEpoch(expected: number): void {
  if (epoch !== expected) {
    throw { status: 401, code: 'AUTH_SESSION_CHANGED', message: 'Authentication session changed' }
  }
}

// invalidateCentralTransport expires only the central context observed by its caller.
// A stale request or repeated notification returns false without touching the current
// identity. Subscribers run synchronously after the old transport has been removed.
export function invalidateCentralTransport(expected: number): boolean {
  if (epoch !== expected || central === null) return false
  replaceAuthentication()
  for (const listener of expirationListeners) listener(expected)
  return true
}

// subscribeCentralExpiration registers a store callback and returns its disposal function.
// The owner must dispose the subscription with its store scope. Explicit session
// adoption does not notify subscribers, because the adopting store publishes that state.
export function subscribeCentralExpiration(listener: (expiredEpoch: number) => void): () => void {
  expirationListeners.add(listener)
  return () => {
    expirationListeners.delete(listener)
  }
}

// isCentralAuthenticationPath recognizes the reserved same-origin central authentication API.
export function isCentralAuthenticationPath(url: string | undefined): boolean {
  return /^\/auth\/central\//.test(url || '')
}
