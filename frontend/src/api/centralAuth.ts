import type { AxiosRequestConfig } from 'axios'
import { apiClient } from './client'
import type { ActionCaptchaRequestProof } from './auth.types'
import type { User } from './identity.types'
import { authenticationEpoch, type AuthenticationRequest } from './authenticationContext'

// centralAuth.ts exchanges browser login intent and session metadata with GetTok's
// central authentication backend. Authorization codes and provider tokens remain on
// the server, while the browser receives only a navigation destination, account
// profile, CSRF proof, and absolute session expiration.

// CentralProvider identifies one advertised upstream provider and its display label.
export interface CentralProvider {
  id: string // Server-registered provider identifier.
  label: string // User-visible provider label.
}

// CentralConfiguration advertises available login entries and explicit legacy migration support.
export interface CentralConfiguration {
  enabled: boolean // Central authentication availability.
  provider_name: string // Default authority display name.
  providers: CentralProvider[] // Direct upstream login entries.
  legacy_binding_enabled: boolean // Owner-approved migration availability.
}

// CentralLoginSelection distinguishes central provider buttons from legacy OAuth entries.
export interface CentralLoginSelection {
  provider: 'central' // Central authentication boundary discriminator.
  identityProvider?: string // Advertised upstream provider identifier.
}

// CentralStartRequest separates login, explicit registration, and existing-account binding.
// The backend validates each intent independently. Binding proof is accepted only when
// the owner has enabled that migration path; ordinary login never selects a local user.
export interface CentralStartRequest extends ActionCaptchaRequestProof {
  intent: 'login' | 'register' | 'bind' // Explicit account operation intent.
  provider?: string // Registered upstream provider identifier.
  invitation_code?: string // Product registration invitation proof.
  password?: string // Fresh legacy ownership proof.
  totp_code?: string // Existing legacy second-factor proof.
}

// CentralSession exposes product identity without disclosing an authentication bearer credential.
export interface CentralSession {
  user: User // Existing product account profile.
  csrf_token: string // Session anti-CSRF proof.
  expires_at: string // Absolute RFC3339 session deadline.
  auth_mode: 'central' // Server-owned authentication mode.
}

// configuration reads the centrally configured entry points without requiring a session.
async function configuration(): Promise<CentralConfiguration> {
  const { data } = await apiClient.get<CentralConfiguration>('/auth/central/config')
  return data
}

// start records explicit browser intent before navigating to the configured authority.
// Only binding carries the legacy bearer needed to prove the existing product owner.
// Navigation URLs must use HTTPS, except matching loopback development hosts.
async function start(request: CentralStartRequest): Promise<{ authorization_url: string }> {
  const options: AxiosRequestConfig & { allowLegacyIdentityBinding: boolean } = {
    allowLegacyIdentityBinding: request.intent === 'bind',
  }
  const { data } = await apiClient.post<{ authorization_url: string }>(
    '/auth/central/start',
    request,
    options,
  )
  const target = new URL(data.authorization_url)
  const loopback = ['127.0.0.1', '[::1]', 'localhost']
  if (
    target.username ||
    target.password ||
    (target.protocol !== 'https:' &&
      !(
        target.protocol === 'http:' &&
        loopback.includes(target.hostname) &&
        loopback.includes(window.location.hostname)
      ))
  )
    throw new Error('Invalid authentication destination')
  return { authorization_url: target.href }
}

// session restores the server-owned cookie session and its current product profile.
async function session(): Promise<CentralSession> {
  const { data } = await apiClient.get<CentralSession>('/auth/central/session')
  return data
}

// logout revokes the current cookie session using the memory-held anti-CSRF proof.
// Network and storage failures propagate so callers can offer a real retry. A local
// state change must not be reported as completed server-side session revocation. The
// captured owner reaches Axios before its asynchronous request queue can select headers.
// Callers may supply the generation that owned an earlier session decision; omitting
// it captures the owner immediately when this operation starts.
async function logout(expectedEpoch = authenticationEpoch()): Promise<void> {
  const options: AxiosRequestConfig & Pick<AuthenticationRequest, '_authenticationEpoch'> = {
    _authenticationEpoch: expectedEpoch,
  }
  await apiClient.post('/auth/central/logout', undefined, options)
}

// centralAuthAPI groups the browser-facing operations of the central authentication boundary.
export const centralAuthAPI = { configuration, start, session, logout }
