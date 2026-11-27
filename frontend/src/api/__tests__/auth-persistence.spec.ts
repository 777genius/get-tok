import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import type { InternalAxiosRequestConfig } from 'axios'

// auth-persistence.spec.ts checks the persistent publication boundary of legacy
// password, TOTP and registration responses when another session is adopted.
// The real Axios client validates a successful response before a later interceptor
// deliberately holds its delivery to the authentication API. This ordering covers
// the gap between transport validation and the API's browser-storage side effects.
//
// The adapter supplies completed authentication data without contacting a provider.
// Session replacement happens after the transport fence and before publication,
// so each API must reject independently of the store's subsequent checks. The
// assertions preserve the newly adopted central context and require all legacy
// credential storage keys to remain absent. Logout fixtures also use the real
// request and response interceptors: refusal must preserve retry state, an empty
// refresh payload still reaches the server, and queued withdrawal cannot borrow
// credentials from a replacement identity.

vi.mock('@/i18n', () => ({ getLocale: () => 'en' }))

beforeEach(() => {
  vi.resetModules()
  localStorage.clear()
  sessionStorage.clear()
  window.history.replaceState({}, '', '/logout-retry-fixture')
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('authentication publication ownership', () => {
  // The shared response fence has already accepted the legacy response when a
  // central session is adopted. The API must still refuse its later storage writes.
  it.each(['login', 'login2FA', 'register'] as const)(
    'rejects stale %s publication after response interceptors complete',
    async (method) => {
      const { apiClient } = await import('@/api/client')
      const auth = await import('@/api/auth')
      const context = await import('@/api/authenticationContext')
      const entered = Promise.withResolvers<void>()
      const release = Promise.withResolvers<void>()
      apiClient.defaults.adapter = async (config) => ({
        config,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          code: 0,
          data: {
            access_token: 'earlier-access',
            refresh_token: 'earlier-refresh',
            expires_in: 3600,
            token_type: 'Bearer',
            user: { id: 7, email: 'earlier@example.invalid' },
          },
        },
      })
      const held = apiClient.interceptors.response.use(async (response) => {
        entered.resolve()
        await release.promise
        return response
      })
      try {
        const request =
          method === 'login'
            ? auth.login({ email: 'earlier@example.invalid', password: 'fixture-only' })
            : method === 'login2FA'
              ? auth.login2FA({ temp_token: 'fixture-challenge', totp_code: '123456' })
              : auth.register({ email: 'earlier@example.invalid', password: 'fixture-only' })
        const rejected = expect(request).rejects.toMatchObject({ code: 'AUTH_SESSION_CHANGED' })
        await entered.promise
        context.replaceAuthentication({
          csrfToken: 'current-central-proof',
          expiresAt: Date.now() + 300_000,
        })
        release.resolve()
        await rejected
        for (const key of ['auth_token', 'refresh_token', 'auth_user', 'token_expires_at']) {
          expect(localStorage.getItem(key)).toBeNull()
        }
        expect(context.centralTransport()?.csrfToken).toBe('current-central-proof')
      } finally {
        // Release and detach the test-owned response barrier even when an assertion
        // fails, preventing this fixture from retaining another pending response.
        release.resolve()
        apiClient.interceptors.response.eject(held)
      }
    },
  )
})

describe('server-confirmed logout transport', () => {
  // The server can reject an unknown or unproven cookie while legacy credentials remain stored.
  // No refusal may trigger bearer refresh, storage cleanup, or navigation before a successful withdrawal.
  it.each([401, 403, 503])('preserves generic logout retry state on HTTP %s', async (status) => {
    const { apiClient } = await import('@/api/client')
    const auth = await import('@/api/auth')
    localStorage.setItem('auth_token', 'retained-access')
    localStorage.setItem('refresh_token', 'retained-refresh')
    localStorage.setItem('auth_user', '{"id":7}')
    localStorage.setItem('token_expires_at', '9999999999999')
    const keys = ['auth_token', 'refresh_token', 'auth_user', 'token_expires_at']
    const retained = keys.map((key) => localStorage.getItem(key))
    const initialURL = window.location.href
    const { default: axios } = await import('axios')
    const refresh = vi.spyOn(axios, 'post').mockRejectedValue(new Error('Unexpected refresh'))
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      throw {
        config,
        response: {
          status,
          data: { code: 'CENTRAL_REFUSED', message: 'Withdrawal requires confirmation' },
          headers: {},
        },
      }
    })
    apiClient.defaults.adapter = adapter

    await expect(auth.logout()).rejects.toMatchObject({ status })
    expect(adapter).toHaveBeenCalledTimes(1)
    expect(adapter.mock.calls[0][0].headers.get('Authorization')).toBeUndefined()
    expect(refresh).not.toHaveBeenCalled()
    expect(keys.map((key) => localStorage.getItem(key))).toEqual(retained)
    expect(sessionStorage.getItem('auth_expired')).toBeNull()
    expect(window.location.href).toBe(initialURL)
  })

  // Missing refresh storage cannot prove that the opaque browser cookie has been revoked.
  // The generic request must reach the server with an empty body and retain local values on rejection.
  it.each([200, 503])('sends empty-refresh logout and observes HTTP %s', async (status) => {
    const { apiClient } = await import('@/api/client')
    const auth = await import('@/api/auth')
    localStorage.setItem('auth_token', 'unconfirmed-access')
    localStorage.setItem('auth_user', '{"id":7}')
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      if (status !== 200) {
        throw {
          config,
          response: { status, data: { code: 'CENTRAL_UNAVAILABLE' }, headers: {} },
        }
      }
      return {
        config,
        status,
        statusText: 'OK',
        headers: {},
        data: { code: 0, data: {} },
      }
    })
    apiClient.defaults.adapter = adapter

    if (status === 200) {
      await expect(auth.logout()).resolves.toBeUndefined()
      expect(localStorage.getItem('auth_token')).toBeNull()
      expect(localStorage.getItem('auth_user')).toBeNull()
    } else {
      await expect(auth.logout()).rejects.toMatchObject({ status })
      expect(localStorage.getItem('auth_token')).toBe('unconfirmed-access')
      expect(localStorage.getItem('auth_user')).toBe('{"id":7}')
    }
    expect(adapter).toHaveBeenCalledTimes(1)
    expect(JSON.parse(adapter.mock.calls[0][0].data)).toEqual({})
    expect(adapter.mock.calls[0][0].headers.get('Authorization')).toBeUndefined()
  })

  // Both logout APIs can wait in Axios after their owner has already been selected.
  // A replacement before shared request interception must reject without any server dispatch or new-owner cleanup.
  it.each([
    ['central', false],
    ['central', true],
    ['legacy', false],
    ['legacy', true],
  ] as const)(
    'keeps %s logout dispatch bound to its owner for replacement=%s',
    async (kind, replaced) => {
      const { apiClient } = await import('@/api/client')
      const auth = await import('@/api/auth')
      const { centralAuthAPI } = await import('@/api/centralAuth')
      const context = await import('@/api/authenticationContext')
      localStorage.setItem('auth_token', 'earlier-access')
      localStorage.setItem('refresh_token', 'earlier-refresh')
      if (kind === 'central') {
        context.replaceAuthentication({
          csrfToken: 'earlier-proof',
          expiresAt: Date.now() + 300_000,
        })
      }
      const owner = context.authenticationEpoch()
      const entered = Promise.withResolvers<void>()
      const release = Promise.withResolvers<void>()
      const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => ({
        config,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { code: 0, data: { revoked: true } },
      }))
      apiClient.defaults.adapter = adapter
      const barrier = apiClient.interceptors.request.use(async (config) => {
        entered.resolve()
        await release.promise
        return config
      })

      try {
        const request = kind === 'central' ? centralAuthAPI.logout(owner) : auth.logout(owner)
        const completed = replaced
          ? expect(request).rejects.toMatchObject({ code: 'AUTH_SESSION_CHANGED' })
          : expect(request).resolves.toBeUndefined()
        await entered.promise
        if (replaced) {
          context.replaceAuthentication({
            csrfToken: 'replacement-proof',
            expiresAt: Date.now() + 300_000,
          })
          localStorage.setItem('auth_token', 'replacement-access')
          localStorage.setItem('refresh_token', 'replacement-refresh')
        }
        release.resolve()
        await completed
        expect(adapter).toHaveBeenCalledTimes(replaced ? 0 : 1)
        if (replaced) {
          expect(context.centralTransport()?.csrfToken).toBe('replacement-proof')
          expect(localStorage.getItem('auth_token')).toBe('replacement-access')
          expect(localStorage.getItem('refresh_token')).toBe('replacement-refresh')
        } else {
          const dispatched = adapter.mock.calls[0][0]
          expect(dispatched.headers.get('Authorization')).toBeUndefined()
          if (kind === 'central') {
            expect(dispatched.headers.get('X-CSRF-Token')).toBe('earlier-proof')
          } else {
            expect(JSON.parse(dispatched.data)).toEqual({ refresh_token: 'earlier-refresh' })
            expect(localStorage.getItem('auth_token')).toBeNull()
            expect(localStorage.getItem('refresh_token')).toBeNull()
          }
        }
        expect(sessionStorage.getItem('auth_expired')).toBeNull()
      } finally {
        // Release and remove the request barrier even after a failed assertion so
        // subsequent requests cannot inherit a pending authentication queue.
        release.resolve()
        apiClient.interceptors.request.eject(barrier)
      }
    },
  )

  // A successful generic reply can be held after transport validation but before API cleanup.
  // A later session owns its stored values even when the earlier withdrawal has already succeeded.
  it('preserves replacement credentials across late logout completion', async () => {
    const { apiClient } = await import('@/api/client')
    const auth = await import('@/api/auth')
    const context = await import('@/api/authenticationContext')
    localStorage.setItem('auth_token', 'earlier-access')
    localStorage.setItem('refresh_token', 'earlier-refresh')
    apiClient.defaults.adapter = async (config) => ({
      config,
      status: 200,
      statusText: 'OK',
      headers: {},
      data: { code: 0, data: {} },
    })
    const entered = Promise.withResolvers<void>()
    const release = Promise.withResolvers<void>()
    const barrier = apiClient.interceptors.response.use(async (response) => {
      entered.resolve()
      await release.promise
      return response
    })

    try {
      const pending = auth.logout()
      await entered.promise
      context.replaceAuthentication({
        csrfToken: 'replacement-proof',
        expiresAt: Date.now() + 300_000,
      })
      localStorage.setItem('auth_token', 'replacement-access')
      localStorage.setItem('refresh_token', 'replacement-refresh')
      release.resolve()
      await pending
      expect(context.centralTransport()?.csrfToken).toBe('replacement-proof')
      expect(localStorage.getItem('auth_token')).toBe('replacement-access')
      expect(localStorage.getItem('refresh_token')).toBe('replacement-refresh')
    } finally {
      // The completed response is always released before removing this test-owned
      // interceptor, preserving independent delivery for the next test.
      release.resolve()
      apiClient.interceptors.response.eject(barrier)
    }
  })
})
