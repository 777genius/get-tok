import { getLocale, setLocale } from '@/i18n'
import { defineStore } from 'pinia'
import { ref, computed, readonly, onScopeDispose } from 'vue'
import { authAPI, isTotp2FARequired, passkeyAPI, type LoginResponse } from '@/api'
import type { User } from '@/api/identity.types'
import { centralAuthAPI, type CentralSession } from '@/api/centralAuth'
import {
  authenticationEpoch,
  assertAuthenticationEpoch,
  replaceAuthentication,
  centralTransport,
  invalidateCentralTransport,
  subscribeCentralExpiration,
} from '@/api/authenticationContext'
import type {
  LoginRequest,
  RegisterRequest,
  AuthResponse,
  ActionCaptchaRequestProof,
} from '@/api/auth.types'

// auth.ts restores browser authentication, publishes signed-in users, and manages user
// polling and proactive token renewal. Central sessions use HttpOnly cookies and memory-only
// profile/CSRF state; legacy authentication requires both a token and user,
// while pending external authentication remains a separate persisted session. Login
// responses and callback tokens follow different publication sequences because callbacks
// can already have stored refresh credentials.
//
// Locale synchronization tracks the last user identifier so background profile polling
// does not replace a language selected during the session. Timers are stopped before
// callback session replacement and local logout. Authentication generations fence profile,
// renewal, restoration, and logout completions before they can change a later session.
// Central deadlines never extend through profile polling, and failed central revocation
// remains an error so the user can retry the server operation.

// Authentication storage keys name the persisted session records read during initial
// navigation and removed by local logout.
const AUTH_TOKEN_KEY = 'auth_token'
const AUTH_USER_KEY = 'auth_user'
const REFRESH_TOKEN_KEY = 'refresh_token'
const TOKEN_EXPIRES_AT_KEY = 'token_expires_at' // Absolute expiry timestamp key.
const PENDING_AUTH_SESSION_KEY = 'pending_auth_session'
const AUTO_REFRESH_INTERVAL = 60 * 1000 // 60 seconds for user data refresh
const TOKEN_REFRESH_BUFFER = 120 * 1000 // 120 seconds before expiry to refresh token

// PendingAuthTokenField identifies the request property accepted by pending
// authentication endpoints.
type PendingAuthTokenField = 'pending_auth_token' | 'pending_oauth_token'

// PendingAuthSessionSummary stores external sign-in context while registration or
// account adoption remains incomplete.
interface PendingAuthSessionSummary {
  // token can be empty for a pending OAuth adoption session; a nonblank provider is what
  // makes the persisted summary resumable.
  token: string // External session token text.
  token_field: PendingAuthTokenField // Request token property name.
  provider: string // External identity provider name.
  redirect?: string // Post-authentication destination when supplied.
  adoption_required?: boolean // Account adoption requirement hint.
  suggested_display_name?: string // Suggested account display name.
  suggested_avatar_url?: string // Suggested account avatar URL.
}

// normalizePendingAuthTokenField maps persisted token-field names to the two supported
// request properties. Unknown values use pending_auth_token so older or incomplete
// storage retains the default authentication field.
function normalizePendingAuthTokenField(value: unknown): PendingAuthTokenField {
  return value === 'pending_oauth_token' ? 'pending_oauth_token' : 'pending_auth_token'
}

// getPersistedPendingAuthSession reads and validates the pending external authentication
// summary. Missing storage returns null; malformed JSON or a blank provider removes the
// entry, while absent optional values remain undefined.
function getPersistedPendingAuthSession(): PendingAuthSessionSummary | null {
  const raw = localStorage.getItem(PENDING_AUTH_SESSION_KEY)
  if (!raw) {
    return null
  }

  try {
    const parsed = JSON.parse(raw) as Partial<PendingAuthSessionSummary> | null
    const provider = typeof parsed?.provider === 'string' ? parsed.provider.trim() : ''
    if (!provider) {
      // A missing provider makes the saved context unusable for external authentication,
      // so remove it before allowing callers to resume.
      localStorage.removeItem(PENDING_AUTH_SESSION_KEY)
      return null
    }
    return {
      token: typeof parsed?.token === 'string' ? parsed.token : '',
      token_field: normalizePendingAuthTokenField(parsed?.token_field),
      provider,
      redirect: typeof parsed?.redirect === 'string' ? parsed.redirect : undefined,
      adoption_required:
        typeof parsed?.adoption_required === 'boolean' ? parsed.adoption_required : undefined,
      suggested_display_name:
        typeof parsed?.suggested_display_name === 'string'
          ? parsed.suggested_display_name
          : undefined,
      suggested_avatar_url:
        typeof parsed?.suggested_avatar_url === 'string' ? parsed.suggested_avatar_url : undefined,
    }
  } catch {
    // Invalid JSON cannot provide a resumable provider context, so remove that persisted
    // entry and return an absent pending session.
    localStorage.removeItem(PENDING_AUTH_SESSION_KEY)
    return null
  }
}

// persistPendingAuthSession serializes the pending external authentication summary into
// browser storage.
function persistPendingAuthSession(session: PendingAuthSessionSummary): void {
  localStorage.setItem(PENDING_AUTH_SESSION_KEY, JSON.stringify(session))
}

// clearPendingAuthSessionStorage removes the persisted pending authentication summary
// from browser storage.
function clearPendingAuthSessionStorage(): void {
  localStorage.removeItem(PENDING_AUTH_SESSION_KEY)
}

// useAuthStore exposes the browser session, account identity, and authentication
// actions. Install Pinia before calling it; session restoration is initiated separately
// through checkAuth, and logout clears locally owned refresh timers.
export const useAuthStore = defineStore('auth', () => {
  // localeUserID records the last account whose language was applied; failed locale
  // loading clears the marker so later profile refreshes can retry.
  let localeUserID: number | null = null

  // syncUserLocale applies the account preference once for each observed user
  // identifier. It records that identifier before awaiting locale loading so repeated
  // profile responses do not restart the same work. A failed locale change clears the
  // marker and permits another profile response to retry. An absent preference keeps the
  // current locale and enables the locale helper's persistence behavior. Already running
  // locale requests are managed by setLocale.
  async function syncUserLocale(value: User): Promise<void> {
    if (localeUserID === value.id) return
    localeUserID = value.id
    try {
      await setLocale(value.preferred_locale || getLocale(), !value.preferred_locale)
    } catch {
      // A failed locale load leaves synchronization incomplete, so clear the account
      // marker and let a later profile refresh retry.
      localeUserID = null
    }
  }

  // Session refs publish authentication to navigation and account consumers; refresh
  // credentials and expiry remain internal to the store-owned renewal timer.
  const user = ref<User | null>(null)
  const token = ref<string | null>(null)
  const authMode = ref<'legacy' | 'central' | null>(null) // Active credential transport.
  let centralEpoch: number | null = null // Owned cookie session generation.
  let initialization: Promise<void> | null = null // Concurrent restoration flight.
  const refreshTokenValue = ref<string | null>(null)
  const tokenExpiresAt = ref<number | null>(null) // Unix epoch milliseconds.
  const pendingAuthSession = ref<PendingAuthSessionSummary | null>(null)
  let refreshIntervalId: ReturnType<typeof setInterval> | null = null
  let tokenRefreshTimeoutId: ReturnType<typeof setTimeout> | null = null

  // Authentication selectors require both token and user for sign-in, inspect the user
  // role for administrator access, and keep pending external sessions separate.
  const isAuthenticated = computed(() => {
    return (authMode.value === 'central' || !!token.value) && !!user.value
  })

  const isAdmin = computed(() => {
    return user.value?.role === 'admin'
  })

  const hasPendingAuthSession = computed(() => pendingAuthSession.value !== null)

  // checkAuth restores token, user, refresh credentials, and pending authentication from
  // browser storage. Call it during initial navigation before evaluating route
  // permissions. A restored user starts a background profile read and periodic refresh;
  // a stored expiry of zero still schedules token renewal. Synchronous restoration
  // failures clear authentication while retaining a valid pending external session.
  // Profile request failures are logged asynchronously and do not block initial route
  // matching.
  function checkAuth(): void {
    if (authMode.value === 'central') return
    const savedToken = localStorage.getItem(AUTH_TOKEN_KEY)
    const savedUser = localStorage.getItem(AUTH_USER_KEY)
    const savedRefreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
    const savedExpiresAt = localStorage.getItem(TOKEN_EXPIRES_AT_KEY)
    pendingAuthSession.value = getPersistedPendingAuthSession()

    if (savedToken && savedUser) {
      try {
        if (token.value !== savedToken) replaceAuthentication()
        authMode.value = 'legacy'
        token.value = savedToken
        user.value = JSON.parse(savedUser)
        refreshTokenValue.value = savedRefreshToken
        tokenExpiresAt.value = savedExpiresAt ? parseInt(savedExpiresAt, 10) : null
        // Restore cached identity immediately for route checks; refresh it
        // asynchronously so network latency does not block initial navigation.
        refreshUser().catch((error) => {
          console.error('Failed to refresh user on init:', error)
        })
        startAutoRefresh()
        if (savedRefreshToken && tokenExpiresAt.value !== null) {
          scheduleTokenRefreshAt(tokenExpiresAt.value)
        }
      } catch (error) {
        console.error('Failed to parse saved user data:', error)
        clearAuth({ preservePendingAuthSession: true })
      }
    }
  }

  // startAutoRefresh replaces the owned profile-polling interval with a sixty-second
  // timer. Each tick checks for a token before requesting the user, and failures are
  // logged while polling continues.
  function startAutoRefresh(): void {
    // Replace the existing polling interval before creating another, so repeated
    // restoration or login does not accumulate profile timers.
    stopAutoRefresh()

    refreshIntervalId = setInterval(() => {
      if (isAuthenticated.value) {
        refreshUser().catch((error) => {
          console.error('Auto-refresh user failed:', error)
        })
      }
    }, AUTO_REFRESH_INTERVAL)
  }

  // stopAutoRefresh releases the owned profile-polling timer and clears its handle.
  // Repeated calls have no further effect after cleanup. Earlier profile requests
  // continue, but generation checks prevent publication after a session replacement.
  function stopAutoRefresh(): void {
    if (refreshIntervalId) {
      // Release the interval before clearing its handle so subsequent startup can
      // register exactly one owned profile poller.
      clearInterval(refreshIntervalId)
      refreshIntervalId = null
    }
  }

  // scheduleTokenRefreshAt replaces the renewal timeout using an absolute millisecond
  // expiry. Expired tokens and tokens within the two-minute buffer refresh immediately;
  // later expiries schedule one timeout for the remaining delay.
  function scheduleTokenRefreshAt(expiresAtMs: number): void {
    // Replace the previous renewal schedule before calculating this expiry, so only the
    // latest scheduled timeout remains owned by the store.
    if (tokenRefreshTimeoutId) {
      clearTimeout(tokenRefreshTimeoutId)
      tokenRefreshTimeoutId = null
    }
    const now = Date.now()
    // Subtract the renewal buffer from the absolute deadline and clamp overdue work to
    // immediate execution rather than a negative timeout.
    const refreshInMs = Math.max(0, expiresAtMs - now - TOKEN_REFRESH_BUFFER)

    if (refreshInMs <= 0) {
      performTokenRefresh()
      return
    }

    tokenRefreshTimeoutId = setTimeout(() => {
      performTokenRefresh()
    }, refreshInMs)
  }

  // scheduleTokenRefresh converts a relative expiry in seconds to an absolute
  // millisecond deadline. It publishes that deadline in reactive state before writing
  // browser storage, then delegates timeout replacement to scheduleTokenRefreshAt. A
  // reload can therefore restore the same stored deadline used for scheduling. Storage
  // failure propagates before scheduling begins, and already elapsed or near-expiry
  // deadlines are handled by the delegated immediate-refresh path rather than by this
  // conversion.
  function scheduleTokenRefresh(expiresInSeconds: number): void {
    const expiresAtMs = Date.now() + expiresInSeconds * 1000
    // Publish and persist the same absolute deadline before scheduling, so a reload can
    // restore the timestamp used by this renewal.
    tokenExpiresAt.value = expiresAtMs
    localStorage.setItem(TOKEN_EXPIRES_AT_KEY, String(expiresAtMs))
    scheduleTokenRefreshAt(expiresAtMs)
  }

  // performTokenRefresh requests replacement credentials when a refresh token is
  // present. The API owns credential persistence; this store publishes returned tokens
  // and schedules their next expiry, logging failures while HTTP authentication handling
  // remains responsible for rejection.
  async function performTokenRefresh(): Promise<void> {
    if (authMode.value === 'central' || !refreshTokenValue.value) {
      return
    }

    try {
      const expected = authenticationEpoch()
      const response = await authAPI.refreshToken()
      assertAuthenticationEpoch(expected)
      // Publish the renewed access and refresh tokens before scheduling their expiry;
      // credential storage is handled by the API request implementation.
      token.value = response.access_token
      refreshTokenValue.value = response.refresh_token
      scheduleTokenRefresh(response.expires_in)
    } catch (error) {
      // Keep the current local session after renewal failure; HTTP authentication
      // handling decides whether a rejected credential requires sign-out.
      console.error('Token refresh failed:', error)
    }
  }

  // stopTokenRefresh releases the owned renewal timeout and clears its handle.
  // Repeated calls after cleanup do nothing. Renewal requests already in flight
  // continue, but generation checks reject publication for a replaced session.
  function stopTokenRefresh(): void {
    if (tokenRefreshTimeoutId) {
      clearTimeout(tokenRefreshTimeoutId)
      tokenRefreshTimeoutId = null
    }
  }

  // login authenticates credentials and returns either a session response or a two-factor challenge. Challenges leave the current state unchanged; other successes
  // publish authentication, while failures clear authentication and retain pending
  // external-session state when present.
  async function login(credentials: LoginRequest): Promise<LoginResponse> {
    const expected = authenticationEpoch()
    try {
      const response = await authAPI.login(credentials)
      if (isTotp2FARequired(response)) {
        return response
      }
      assertAuthenticationEpoch(expected)
      setAuthFromResponse(response)

      return response
    } catch (error) {
      if (authenticationEpoch() === expected) {
        clearAuth({ preservePendingAuthSession: pendingAuthSession.value !== null })
      }
      throw error
    }
  }

  // login2FA exchanges the temporary login token and supplied code for an authenticated
  // user. Success publishes the response through the shared session helper; failure
  // clears authentication while retaining an existing pending external session.
  async function login2FA(tempToken: string, totpCode: string): Promise<User> {
    const expected = authenticationEpoch()
    try {
      const response = await authAPI.login2FA({ temp_token: tempToken, totp_code: totpCode })
      assertAuthenticationEpoch(expected)
      setAuthFromResponse(response)
      return user.value!
    } catch (error) {
      if (authenticationEpoch() === expected) {
        clearAuth({ preservePendingAuthSession: pendingAuthSession.value !== null })
      }
      throw error
    }
  }

  // loginWithPasskey authenticates through the passkey API with optional action-captcha
  // proof. Success uses the shared session publication path, and failure clears
  // authentication while preserving pending external-session state when present.
  async function loginWithPasskey(proof?: ActionCaptchaRequestProof): Promise<User> {
    const expected = authenticationEpoch()
    try {
      const response = await passkeyAPI.login(proof)
      assertAuthenticationEpoch(expected)
      setAuthFromResponse(response)
      return user.value!
    } catch (error) {
      if (authenticationEpoch() === expected) {
        clearAuth({ preservePendingAuthSession: pendingAuthSession.value !== null })
      }
      throw error
    }
  }

  // setAuthFromResponse publishes a successful login under a new authentication generation.
  // Callers must verify their request generation before entering this synchronous helper.
  // The helper owns rollback after replacement because the caller still observes its
  // earlier generation and must not clear a newer session. Fallible storage writes,
  // pending-session cleanup, and timer setup remain inside that ownership boundary.
  // Any publication failure clears partial credentials and timers only while this
  // installed generation remains current, preserving a later replacement's authority.
  function setAuthFromResponse(response: AuthResponse): void {
    stopAutoRefresh()
    stopTokenRefresh()
    const installedEpoch = replaceAuthentication()
    try {
      centralEpoch = null
      authMode.value = 'legacy'
      refreshTokenValue.value = null
      tokenExpiresAt.value = null
      localStorage.removeItem(REFRESH_TOKEN_KEY)
      localStorage.removeItem(TOKEN_EXPIRES_AT_KEY)
      token.value = response.access_token
      if (response.refresh_token) {
        refreshTokenValue.value = response.refresh_token
        localStorage.setItem(REFRESH_TOKEN_KEY, response.refresh_token)
      }

      // Persist the response credentials before starting locale synchronization, so
      // failed browser publication does not apply preferences from an abandoned session.
      const userData = response.user
      user.value = userData
      localStorage.setItem(AUTH_TOKEN_KEY, response.access_token)
      localStorage.setItem(AUTH_USER_KEY, JSON.stringify(userData))
      clearPendingAuthSession()
      startAutoRefresh()
      if (response.refresh_token && response.expires_in) {
        scheduleTokenRefresh(response.expires_in)
      }
      void syncUserLocale(userData)
    } catch (error) {
      // Publication may fail after ownership advances, so the publishing generation
      // must clear its own partial session before returning the storage error.
      if (authenticationEpoch() === installedEpoch) {
        clearAuth({ preservePendingAuthSession: pendingAuthSession.value !== null })
      }
      throw error
    }
  }

  // register creates an account and publishes the returned authenticated user through
  // the shared session helper. Failures clear authentication, preserve an existing
  // pending external session, and propagate the error to the registration form.
  async function register(userData: RegisterRequest): Promise<User> {
    const expected = authenticationEpoch()
    try {
      const response = await authAPI.register(userData)
      assertAuthenticationEpoch(expected)
      setAuthFromResponse(response)

      return user.value!
    } catch (error) {
      if (authenticationEpoch() === expected) {
        clearAuth({ preservePendingAuthSession: pendingAuthSession.value !== null })
      }
      throw error
    }
  }

  // setToken installs an access token supplied by an external authentication callback
  // and loads its user. Existing timers and reactive user identity are cleared before
  // the new token is published and persisted. Refresh credentials are read from storage
  // because the callback can already have written them. User loading completes before
  // polling and renewal restart. Failure clears authentication while retaining pending
  // external-session state when present; in-flight requests are not cancelled here.
  async function setToken(newToken: string): Promise<User> {
    replaceAuthentication()
    centralEpoch = null
    authMode.value = 'legacy'
    const expected = authenticationEpoch()
    // Stop owned timers before replacing session identity; callback-written refresh
    // credentials remain in storage for the new access token to adopt.
    stopAutoRefresh()
    stopTokenRefresh()
    token.value = null
    localeUserID = null
    user.value = null

    token.value = newToken
    localStorage.setItem(AUTH_TOKEN_KEY, newToken)
    const savedRefreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
    const savedExpiresAt = localStorage.getItem(TOKEN_EXPIRES_AT_KEY)

    if (savedRefreshToken) {
      refreshTokenValue.value = savedRefreshToken
    }
    if (savedExpiresAt) {
      tokenExpiresAt.value = parseInt(savedExpiresAt, 10)
    }

    try {
      const userData = await refreshUser()
      assertAuthenticationEpoch(expected)
      startAutoRefresh()
      if (savedRefreshToken && tokenExpiresAt.value !== null) {
        scheduleTokenRefreshAt(tokenExpiresAt.value)
      }

      clearPendingAuthSession()
      return userData
    } catch (error) {
      if (authenticationEpoch() === expected) {
        clearAuth({ preservePendingAuthSession: pendingAuthSession.value !== null })
      }
      throw error
    }
  }

  // setPendingAuthSession publishes the pending external authentication summary and
  // updates its browser record. A non-null summary becomes reactive before
  // serialization, while null clears the reactive value before removing storage. This
  // ordering means a storage failure can leave the current reactive value changed while
  // persisted data remains older. Callers that need to end pending authentication use
  // clearPendingAuthSession, which delegates to this same null-setting path.
  function setPendingAuthSession(session: PendingAuthSessionSummary | null): void {
    // Publish the pending session before attempting storage so its reactive value
    // follows the same update order used by the authentication forms.
    pendingAuthSession.value = session

    if (session) {
      persistPendingAuthSession(session)
      return
    }

    clearPendingAuthSessionStorage()
  }

  // clearPendingAuthSession delegates removal of the pending external session to
  // setPendingAuthSession. The reactive summary becomes null before browser storage
  // removal, so a storage error propagates after reactive state has already changed.
  function clearPendingAuthSession(): void {
    setPendingAuthSession(null)
  }

  // logout revokes the currently captured session before clearing its local identity.
  // Central revocation failures propagate for retry; legacy logout retains its historical
  // best-effort behavior. Completion never clears a different session adopted meanwhile.
  async function logout(): Promise<void> {
    const expected = authenticationEpoch()
    if (authMode.value === 'central') {
      await centralAuthAPI.logout()
      if (authenticationEpoch() === expected) clearAuth()
      return
    }
    try {
      await authAPI.logout()
    } catch (err) {
      // Legacy revocation keeps its established local-logout behavior. Ownership is
      // checked again below before removing any state belonging to a later session.
      console.warn('Logout API call failed, clearing local session anyway', err)
    } finally {
      if (authenticationEpoch() === expected) clearAuth()
    }
  }

  // refreshUser refreshes the current product profile without changing session ownership.
  // Central responses stay in memory and must preserve their user, CSRF proof, and
  // original absolute deadline. Legacy responses retain their existing storage format.
  // A response for an earlier generation cannot publish or clear the current identity.
  async function refreshUser(): Promise<User> {
    if (!token.value && authMode.value !== 'central') throw new Error('Not authenticated')
    const expected = authenticationEpoch()
    try {
      let userData: User
      if (authMode.value === 'central') {
        const response = await centralAuthAPI.session()
        assertAuthenticationEpoch(expected)
        const current = centralTransport()
        if (
          response.user.id !== user.value?.id ||
          response.csrf_token !== current?.csrfToken ||
          Date.parse(response.expires_at) !== current?.expiresAt
        ) {
          invalidateCentralTransport(expected)
          throw { status: 401, code: 'AUTH_SESSION_CHANGED' }
        }
        userData = response.user
      } else {
        const response = await authAPI.getCurrentUser()
        assertAuthenticationEpoch(expected)
        userData = response.data
        localStorage.setItem(AUTH_USER_KEY, JSON.stringify(userData))
      }
      user.value = userData
      void syncUserLocale(userData)
      return userData
    } catch (error) {
      if (authenticationEpoch() === expected && (error as { status?: number }).status === 401) {
        clearAuth({ preservePendingAuthSession: pendingAuthSession.value !== null })
      }
      throw error
    }
  }

  // restoreCentralSession adopts only a server-confirmed cookie session with a live deadline.
  // Call it after the fixed central callback or during initial navigation without legacy
  // credentials. The captured generation rejects completion after logout or another login.
  // Adoption removes legacy credentials before publishing the central profile, and its
  // expiry timer clears local authority without attempting token renewal. Background
  // profile polling cannot move that deadline or turn status evidence into authentication.
  async function restoreCentralSession(): Promise<User> {
    const expected = authenticationEpoch()
    const response: CentralSession = await centralAuthAPI.session()
    assertAuthenticationEpoch(expected)
    const expiresAt = Date.parse(response.expires_at)
    if (
      response.auth_mode !== 'central' ||
      !Number.isFinite(expiresAt) ||
      expiresAt <= Date.now() ||
      !response.csrf_token ||
      response.csrf_token.length > 512 ||
      !response.user?.id
    ) {
      throw new Error('Invalid central session response')
    }
    clearAuth()
    centralEpoch = replaceAuthentication({ csrfToken: response.csrf_token, expiresAt })
    authMode.value = 'central'
    user.value = response.user
    void syncUserLocale(response.user)
    startAutoRefresh()
    const adoptedEpoch = centralEpoch
    tokenRefreshTimeoutId = setTimeout(
      () => {
        invalidateCentralTransport(adoptedEpoch)
      },
      Math.min(expiresAt - Date.now(), 2_147_483_647),
    )
    return response.user
  }

  // initializeSession joins initial restoration before navigation evaluates protected routes.
  // Existing legacy credentials retain their established synchronous restore path. Otherwise
  // the backend decides whether an HttpOnly central cookie represents a current session.
  // Anonymous or disabled endpoints are normal; service failures remain observable errors.
  async function initializeSession(): Promise<void> {
    if (initialization) return initialization
    const attempt = (async () => {
      checkAuth()
      if (isAuthenticated.value) return
      try {
        await restoreCentralSession()
      } catch (error) {
        const { status, code } = error as { status?: number; code?: string }
        const disabled = status === 503 && code === 'CENTRAL_DISABLED'
        if (status !== 401 && status !== 404 && !disabled) throw error
      }
    })()
    initialization = attempt
    try {
      await attempt
    } finally {
      if (initialization === attempt) initialization = null
    }
  }

  // The store owns this expiration subscription until disposal. Only its captured
  // central generation can clear its state, so older store instances cannot erase
  // a replacement session when a stale request finally reports unauthorized access.
  const stopCentralExpiration = subscribeCentralExpiration((expiredEpoch) => {
    if (centralEpoch === expiredEpoch) clearAuth()
  })
  onScopeDispose(stopCentralExpiration)

  // clearAuth stops profile and renewal timers before removing reactive and persisted
  // credentials. The optional preservePendingAuthSession flag reloads valid pending
  // external authentication after access-session storage has been cleared. Without that
  // flag, both the pending reactive summary and its storage entry are removed. Timer
  // cleanup does not cancel requests already in flight, and browser storage operations
  // retain their normal failure behavior rather than providing a transaction across
  // keys.
  function clearAuth(options?: {
    // preservePendingAuthSession reloads valid pending external authentication after
    // clearing access credentials; omission clears that pending context as well.
    preservePendingAuthSession?: boolean
  }): void {
    // Release owned refresh timers before clearing credentials so future timer ticks
    // cannot start new profile or token work for the cleared session.
    stopAutoRefresh()
    stopTokenRefresh()

    replaceAuthentication()
    centralEpoch = null
    authMode.value = null
    token.value = null
    refreshTokenValue.value = null
    tokenExpiresAt.value = null
    localeUserID = null
    user.value = null
    localStorage.removeItem(AUTH_TOKEN_KEY)
    localStorage.removeItem(AUTH_USER_KEY)
    localStorage.removeItem(REFRESH_TOKEN_KEY)
    localStorage.removeItem(TOKEN_EXPIRES_AT_KEY)

    if (options?.preservePendingAuthSession) {
      pendingAuthSession.value = getPersistedPendingAuthSession()
      return
    }

    pendingAuthSession.value = null
    clearPendingAuthSessionStorage()
  }

  return {
    user,
    token,
    authMode: readonly(authMode),
    pendingAuthSession: readonly(pendingAuthSession),
    isAuthenticated,
    isAdmin,
    hasPendingAuthSession,
    login,
    loginWithPasskey,
    login2FA,
    register,
    setToken,
    logout,
    checkAuth,
    initializeSession,
    restoreCentralSession,
    refreshUser,
    setPendingAuthSession,
    clearPendingAuthSession,
  }
})
