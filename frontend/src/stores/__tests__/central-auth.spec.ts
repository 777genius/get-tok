import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { centralTransport, replaceAuthentication } from '@/api/authenticationContext'

// central-auth.spec.ts exercises cookie-session publication, expiration, and competing
// authentication completions through the production store. Controlled endpoint promises
// expose races while fake time keeps the server's absolute deadline observable without
// issuing a real identity credential or replacing the backend E2E qualification.

// Endpoint spies control only external effects; the actual store owns timers, browser
// storage, generation checks, and user publication throughout these scenarios.
const endpoints = vi.hoisted(() => ({
  session: vi.fn(), // Central session metadata response.
  logout: vi.fn(), // Durable central logout response.
  login: vi.fn(), // Legacy login response fixture.
  profile: vi.fn(), // Legacy profile response fixture.
  legacyLogout: vi.fn(), // Legacy logout response fixture.
  refresh: vi.fn(), // Legacy token renewal response.
}))
vi.mock('@/api/centralAuth', () => ({ centralAuthAPI: endpoints }))
vi.mock('@/api', () => ({
  authAPI: {
    login: endpoints.login,
    getCurrentUser: endpoints.profile,
    logout: endpoints.legacyLogout,
    refreshToken: endpoints.refresh,
  },
  isTotp2FARequired: () => false,
}))
vi.mock('@/i18n', () => ({
  getLocale: () => 'en',
  setLocale: vi.fn().mockResolvedValue(undefined),
}))

// Product fixtures preserve the local user identifier and balance across authentication
// transport changes. The server fixture supplies the cookie; these tests never fabricate it.
const user = {
  id: 7,
  username: 'local-owner',
  email: 'owner@example.test',
  role: 'user',
  balance: 123,
  concurrency: 5,
  status: 'active',
  allowed_groups: null,
  created_at: '2026-11-26',
  updated_at: '2026-11-26',
}
let store: ReturnType<typeof useAuthStore> // Current isolated test store.

// sessionResponse creates metadata bounded by the current test clock's absolute expiry.
function sessionResponse() {
  return {
    user,
    csrf_token: 'central-csrf-proof',
    expires_at: new Date(Date.now() + 300_000).toISOString(),
    auth_mode: 'central',
  }
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-11-26T12:00:00Z'))
  vi.resetAllMocks()
  localStorage.clear()
  replaceAuthentication()
  setActivePinia(createPinia())
  store = useAuthStore()
  endpoints.session.mockResolvedValue(sessionResponse())
})
afterEach(() => {
  store.$dispose()
  vi.clearAllTimers()
  vi.useRealTimers()
})

describe('central browser session ownership', () => {
  // A central callback replaces earlier legacy credentials with cookie transport.
  // Identity and CSRF state remain in memory, and background reads cannot extend expiry.
  it('keeps cookie authentication in memory and preserves the original deadline', async () => {
    localStorage.setItem('auth_token', 'earlier-bearer')
    localStorage.setItem('refresh_token', 'earlier-refresh')
    localStorage.setItem('auth_user', JSON.stringify(user))
    localStorage.setItem('token_expires_at', '9999999999999')
    await store.restoreCentralSession()
    const original = centralTransport()
    expect(store.isAuthenticated).toBe(true)
    expect(store.authMode).toBe('central')
    expect(store.token).toBeNull()
    expect(store.user?.balance).toBe(123)
    for (const key of ['auth_token', 'refresh_token', 'auth_user', 'token_expires_at']) {
      expect(localStorage.getItem(key)).toBeNull()
    }
    await store.refreshUser()
    expect(centralTransport()).toBe(original)
    expect(localStorage.getItem('auth_user')).toBeNull()
    await vi.advanceTimersByTimeAsync(300_000)
    expect(store.isAuthenticated).toBe(false)
    expect(centralTransport()).toBeNull()
    expect(endpoints.refresh).not.toHaveBeenCalled()
  })

  // An earlier legacy profile request completes after the central callback publishes.
  // Its user and failure cannot overwrite or clear the new cookie-owned identity.
  it('rejects late legacy profile publication after central adoption', async () => {
    endpoints.login.mockResolvedValue({ access_token: 'legacy-token', user })
    await store.login({ email: user.email, password: 'test-only' })
    const pending = Promise.withResolvers<{ data: typeof user }>()
    endpoints.profile.mockReturnValue(pending.promise)
    const obsolete = store.refreshUser()
    const rejected = expect(obsolete).rejects.toMatchObject({ code: 'AUTH_SESSION_CHANGED' })
    await store.restoreCentralSession()
    pending.resolve({ data: { ...user, id: 99 } })
    await rejected
    expect(store.authMode).toBe('central')
    expect(store.user?.id).toBe(7)
    expect(localStorage.getItem('auth_user')).toBeNull()
  })

  // Durable logout may fail while the cookie is still valid on the server.
  // The store reports that failure for retry and clears identity only after success.
  it('requires successful central revocation before reporting logout', async () => {
    await store.restoreCentralSession()
    endpoints.logout.mockRejectedValueOnce({ status: 503 })
    await expect(store.logout()).rejects.toMatchObject({ status: 503 })
    expect(store.isAuthenticated).toBe(true)
    endpoints.logout.mockResolvedValueOnce(undefined)
    await store.logout()
    expect(store.isAuthenticated).toBe(false)
    expect(centralTransport()).toBeNull()
  })

  // Initial restoration is suspended while logout ends the local authentication generation.
  // Completing the old metadata request cannot recreate the cleared session afterward.
  it('cannot resurrect authentication from a late bootstrap response', async () => {
    const pending = Promise.withResolvers<ReturnType<typeof sessionResponse>>()
    endpoints.session.mockReturnValue(pending.promise)
    const obsolete = store.restoreCentralSession()
    const rejected = expect(obsolete).rejects.toMatchObject({ code: 'AUTH_SESSION_CHANGED' })
    await store.logout()
    pending.resolve(sessionResponse())
    await rejected
    expect(store.isAuthenticated).toBe(false)
    expect(centralTransport()).toBeNull()
  })

  // A different server session appears while the existing tab refreshes its profile.
  // Changed identity or CSRF ownership clears the old view instead of silently switching users.
  it('rejects an unannounced cookie identity change during profile refresh', async () => {
    await store.restoreCentralSession()
    endpoints.session.mockResolvedValue({ ...sessionResponse(), user: { ...user, id: 99 } })
    await expect(store.refreshUser()).rejects.toMatchObject({ code: 'AUTH_SESSION_CHANGED' })
    expect(store.isAuthenticated).toBe(false)
  })
})
