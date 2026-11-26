import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'

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
// credential storage keys to remain absent.

vi.mock('@/i18n', () => ({ getLocale: () => 'en' }))

beforeEach(() => {
  vi.resetModules()
  localStorage.clear()
  sessionStorage.clear()
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
