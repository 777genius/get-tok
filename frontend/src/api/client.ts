import axios, { AxiosInstance, AxiosError, AxiosResponse } from 'axios'
import type { ApiResponse } from '@/api/common.types'
import { getLocale } from '@/i18n'
import { responseErrorMessage, localizedErrorMessage } from '@/i18n/errors'
import {
  ADMIN_UI_REQUEST_HEADER,
  USER_UI_REQUEST_HEADER,
  shouldMarkAdminUIRequest,
  shouldMarkUserUIRequest,
} from './adminUIRequest'
import { refreshAuthTokens } from './tokenRefresh'
import { getAPIBaseURL } from './url'
import { isPluginApiPath } from './pluginPaths'
import {
  authenticationEpoch,
  authenticationHeaders,
  assertAuthenticationEpoch,
  centralTransport,
  invalidateCentralTransport,
  isCookieOnlyAuthenticationPath,
  type AuthenticationRequest,
} from './authenticationContext'

/**
 * client.ts configures the browser HTTP client and the interceptors that attach
 * session, locale, timezone and timing metadata. Successful envelope responses
 * expose their data payload, while business and HTTP failures become the error
 * objects consumed by views. Cancellation errors retain their Axios identity so
 * callers can suppress interrupted requests.
 *
 * A GET that completes after a locale switch is replayed through the request
 * interceptor before its result is delivered. A first host authentication failure
 * can refresh and retry with rotated credentials; failed refresh cleanup checks the
 * captured refresh token and serialized user so an earlier request cannot erase
 * a later session. Central cookie sessions attach a memory-only CSRF proof and
 * never enter legacy token refresh. Every dispatched result retains its session
 * generation, so replacement also fences successful earlier responses.
 * Authentication-entry failures remain available to their
 * forms. Marked plugin replies keep their own error semantics and do not change
 * native session or feature state.
 */

export { buildApiUrl, buildGatewayUrl } from './url'

/**
 * apiClient shares authentication and response handling across browser API
 * modules, with cookies enabled and a thirty-second default request timeout.
 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: getAPIBaseURL(),
  withCredentials: true,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

/**
 * getUserTimezone returns the browser's IANA timezone for GET query parameters.
 * If Intl timezone lookup throws, it returns UTC so request construction can
 * continue with a defined timezone value.
 */
const getUserTimezone = (): string => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone
  } catch {
    /**
     * When Intl cannot resolve a timezone, UTC keeps GET date-range defaults
     * defined and lets request construction continue.
     */
    return 'UTC'
  }
}

/**
 * Read browser session and locale at dispatch time so replayed requests receive
 * the credentials and language currently selected.
 */
apiClient.interceptors.request.use(
  (config: AuthenticationRequest) => {
    // Replayed requests retain their original owner while waiting in Axios's
    // interceptor queue. Reject a replaced owner before current headers are captured.
    if (config._authenticationEpoch !== undefined) {
      assertAuthenticationEpoch(config._authenticationEpoch)
    }
    const central = centralTransport()
    config._authenticationEpoch = authenticationEpoch()
    config._centralAuthentication = central !== null || isCookieOnlyAuthenticationPath(config.url)
    // Cookie-only requests never borrow a stored legacy credential. Explicit migration
    // start alone carries that credential as proof of the existing product owner.
    if (config._centralAuthentication && !config.allowLegacyIdentityBinding) {
      config.headers.delete('Authorization')
    }
    Object.assign(
      config.headers,
      authenticationHeaders(config._centralAuthentication && !config.allowLegacyIdentityBinding),
    )

    // Attach locale for backend translations
    if (config.headers) {
      config.headers['Accept-Language'] = getLocale()
    }

    // Native GET queries receive timezone defaults; plugin endpoints own their query contract and receive only explicitly supplied query values.
    if (config.method === 'get' && !isPluginApiPath(config.url)) {
      if (!config.params) {
        config.params = {}
      }
      config.params.timezone = getUserTimezone()
    }

    if (config.headers) {
      const requestURL = String(config.url || '')
      if (shouldMarkAdminUIRequest(requestURL)) {
        config.headers[ADMIN_UI_REQUEST_HEADER] = '1'
      }
      if (shouldMarkUserUIRequest(requestURL)) {
        config.headers[USER_UI_REQUEST_HEADER] = '1'
      }
    }

    return config
  },
  (error) => {
    return Promise.reject(error)
  },
)

// ==================== Response Interceptor ====================

apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    const dispatched = response.config as AuthenticationRequest
    if (dispatched._authenticationEpoch !== undefined) {
      assertAuthenticationEpoch(dispatched._authenticationEpoch)
    }
    /**
     * When a GET finishes after the locale changes, replay it through the request
     * interceptor so the caller receives the current language.
     */
    const requestLocale = response.config?.headers?.['Accept-Language']
    if (response.config?.method === 'get' && requestLocale && requestLocale !== getLocale()) {
      return apiClient.request(response.config)
    }
    // Plugin payloads own their field names, so native envelope interpretation must not consume a plugin's ordinary code or data property.
    if (isPluginApiPath(response.config?.url)) {
      return response
    }
    // Unwrap standard API response format { code, message, data }
    const apiResponse = response.data as ApiResponse<unknown>
    if (apiResponse && typeof apiResponse === 'object' && 'code' in apiResponse) {
      if (apiResponse.code === 0) {
        // Success - return the data portion
        response.data = apiResponse.data
      } else {
        // API error
        const resp = apiResponse as unknown as Record<string, unknown>
        return Promise.reject({
          status: response.status,
          code: apiResponse.code,
          message: responseErrorMessage(
            String(response.config?.url || ''),
            resp.reason,
            response.status,
            apiResponse.message || '',
          ),
          request_id: response.headers?.['x-request-id'],
          reason: resp.reason,
          metadata: resp.metadata,
        })
      }
    }
    return response
  },
  async (error: AxiosError<ApiResponse<unknown>>) => {
    // A request can lose its owner before reaching the adapter. Preserve that
    // local rejection so callers discard stale work without reporting a network outage.
    if (error.code === 'AUTH_SESSION_CHANGED') return Promise.reject(error)
    // Request cancellation: keep the original axios cancellation error so callers can ignore it.
    // Otherwise we'd misclassify it as a generic "network error".
    if (error.code === 'ERR_CANCELED' || axios.isCancel(error)) {
      return Promise.reject(error)
    }

    const originalRequest = error.config as AuthenticationRequest & {
      _retry?: boolean // Refresh retry marker.
    }
    if (originalRequest?._authenticationEpoch !== undefined) {
      assertAuthenticationEpoch(originalRequest._authenticationEpoch)
    }

    // Handle common errors
    if (error.response) {
      const { status, data } = error.response
      const url = String(error.config?.url || '')

      // Validate `data` shape to avoid HTML error pages breaking our error handling.
      const apiData = (typeof data === 'object' && data !== null ? data : {}) as Record<string, any>
      // The host proxy attaches this response marker after native authentication;
      // plugin-owned errors must not rotate host credentials or change native feature flags.
      const pluginResponse =
        isPluginApiPath(url) && error.response.headers?.['x-tokenrouter-plugin-response'] === '1'

      // A central unauthorized response expires only its captured cookie session.
      // Entry-point errors remain on their form, and no central response falls
      // through to legacy bearer refresh or legacy credential cleanup below.
      if (!pluginResponse && status === 401 && originalRequest?._centralAuthentication) {
        const entry = isCookieOnlyAuthenticationPath(url)
        if (
          (!entry || url === '/auth/central/session') &&
          originalRequest._authenticationEpoch !== undefined &&
          invalidateCentralTransport(originalRequest._authenticationEpoch)
        ) {
          sessionStorage.setItem('auth_expired', '1')
          if (!entry && !window.location.pathname.includes('/login')) {
            window.location.href = '/login'
          }
        }
      }

      // Ops monitoring disabled: treat as feature-flagged 404, and proactively redirect away
      // from ops pages to avoid broken UI states.
      if (!pluginResponse && status === 404 && apiData.message === 'Ops monitoring is disabled') {
        try {
          /**
           * Cache the disabled flag before notifying listeners so operations
           * views can stop polling and read the same disabled state.
           */
          localStorage.setItem('ops_monitoring_enabled_cached', 'false')
        } catch {
          // Storage may be unavailable, but the structured disabled-feature error still needs to reach the caller and trigger navigation.
        }
        try {
          window.dispatchEvent(new CustomEvent('ops-monitoring-disabled'))
        } catch {
          // Event dispatch failure must not prevent the disabled-feature response from rejecting or the operations page from redirecting.
        }

        if (window.location.pathname.startsWith('/admin/ops')) {
          window.location.href = '/admin/settings'
        }

        return Promise.reject({
          status,
          code: 'OPS_DISABLED',
          message: apiData.message || error.message,
          url,
        })
      }

      // Native 401 responses may refresh the current host session once.
      // This handles TOKEN_EXPIRED, INVALID_TOKEN, TOKEN_REVOKED, etc.
      if (
        !pluginResponse &&
        status === 401 &&
        !originalRequest?._centralAuthentication &&
        !originalRequest._retry
      ) {
        const refreshToken = localStorage.getItem('refresh_token')
        const isAuthEndpoint =
          url.includes('/auth/login') ||
          url.includes('/auth/register') ||
          url.includes('/auth/refresh') ||
          url.includes('/auth/oauth/google/one-tap')

        // If we have a refresh token and this is not an auth endpoint, try to refresh
        if (refreshToken && !isAuthEndpoint) {
          const refreshSessionUser = localStorage.getItem('auth_user')
          const refreshEpoch = originalRequest._authenticationEpoch ?? authenticationEpoch()
          /**
           * Mark this request before awaiting refresh so a second unauthorized
           * result cannot enter another refresh loop for the same request.
           */
          originalRequest._retry = true

          try {
            const headers = originalRequest.headers as Record<string, unknown> | undefined
            const authHeader = headers?.Authorization ?? headers?.authorization
            const failedAccessToken =
              typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
                ? authHeader.slice('Bearer '.length)
                : null
            const tokens = await refreshAuthTokens({ failedAccessToken })

            // A successful refresh may settle after logout or another login. Check
            // the original owner before retry dispatch can capture the newer session.
            assertAuthenticationEpoch(refreshEpoch)

            /**
             * Retry through the shared client with the rotated access token so
             * authentication headers reflect the completed refresh attempt.
             */
            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${tokens.access_token}`
            }
            return apiClient(originalRequest)
          } catch {
            // Generation changes take precedence over token comparisons, including
            // a replacement login for the same user with otherwise matching storage.
            assertAuthenticationEpoch(refreshEpoch)
            /**
             * A failed refresh for an earlier identity must not clear a later login; compare
             * refresh token and serialized user before cleanup.
             */
            const sessionChanged =
              localStorage.getItem('refresh_token') !== refreshToken ||
              localStorage.getItem('auth_user') !== refreshSessionUser
            if (sessionChanged) {
              return Promise.reject({
                status: 401,
                code: 'AUTH_SESSION_CHANGED',
                message: localizedErrorMessage('AUTH_SESSION_CHANGED', 401),
              })
            }

            // After confirming the captured session still owns storage, remove its credentials before marking expiry and navigating to login.
            localStorage.removeItem('auth_token')
            localStorage.removeItem('refresh_token')
            localStorage.removeItem('auth_user')
            localStorage.removeItem('token_expires_at')
            sessionStorage.setItem('auth_expired', '1')

            if (!window.location.pathname.includes('/login')) {
              window.location.href = '/login'
            }

            return Promise.reject({
              status: 401,
              code: 'TOKEN_REFRESH_FAILED',
              message: localizedErrorMessage('SESSION_EXPIRED', 401),
            })
          }
        }

        // Without a refresh attempt, record whether credentials were present before cleanup so anonymous authentication errors do not show a session-expired notice.
        const hasToken = !!localStorage.getItem('auth_token')
        const headers = error.config?.headers as Record<string, unknown> | undefined
        const authHeader = headers?.Authorization ?? headers?.authorization
        const sentAuth =
          typeof authHeader === 'string'
            ? authHeader.trim() !== ''
            : Array.isArray(authHeader)
              ? authHeader.length > 0
              : !!authHeader

        localStorage.removeItem('auth_token')
        localStorage.removeItem('refresh_token')
        localStorage.removeItem('auth_user')
        localStorage.removeItem('token_expires_at')
        if ((hasToken || sentAuth) && !isAuthEndpoint) {
          sessionStorage.setItem('auth_expired', '1')
        }
        /**
         * Authentication-entry 401 responses belong to the login form; redirecting them
         * as session expiry would hide its credential error.
         */
        if (!isAuthEndpoint && !window.location.pathname.includes('/login')) {
          window.location.href = '/login'
        }
      }

      // Return structured error
      return Promise.reject({
        status,
        code: apiData.code,
        reason: apiData.reason,
        error: apiData.error,
        message: pluginResponse
          ? String(apiData.message || apiData.detail || error.message)
          : responseErrorMessage(
              url,
              apiData.reason,
              status,
              apiData.message || apiData.detail || error.message,
            ),
        request_id: error.response?.headers?.['x-request-id'],
        metadata: apiData.metadata,
      })
    }

    // Network error
    return Promise.reject({
      status: 0,
      message: localizedErrorMessage('NETWORK_ERROR', 0),
    })
  },
)

export default apiClient
