import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import CentralCallbackView from '@/views/auth/CentralCallbackView.vue'

// CentralCallbackView.spec.ts checks the credential-free callback boundary and its
// fixed recovery choices. The production view handles route input and navigation while
// a controlled session endpoint isolates URL rejection from backend token qualification.
//
// Rejected callback input is normalized to one public error identifier rather
// than a success-shaped URL. Remounting from that sanitized location reproduces
// a browser reload and must keep the failure visible even when a usable session
// endpoint exists. Empty, duplicate, and unknown error parameters exercise the
// same rejection boundary as injected credentials, while ordinary success still
// restores the server cookie before protected navigation begins.

// The route fixture supplies only navigation inputs; session restoration and destination
// changes remain independently observable so rejected callbacks cannot appear successful.
const controls = vi.hoisted(() => ({
  route: { query: {} as Record<string, string | string[] | null>, hash: '' }, // Callback URL inputs.
  restore: vi.fn(), // Server-owned session restoration spy.
  replace: vi.fn(), // Protected page navigation spy.
}))
vi.mock('vue-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('vue-router')>()),
  useRoute: () => controls.route,
  useRouter: () => ({ replace: controls.replace }),
}))
vi.mock('vue-i18n', async (importOriginal) => ({
  ...(await importOriginal<typeof import('vue-i18n')>()),
  useI18n: () => ({ t: (key: string) => key }),
}))
vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({ restoreCentralSession: controls.restore, isAdmin: false }),
}))

// A mounted wrapper is retained only until its test finishes. The next case starts
// with fresh route input and browser history, preventing callback query carryover.
let wrapper: ReturnType<typeof mount> | undefined
beforeEach(() => {
  vi.resetAllMocks()
  controls.route.query = {}
  controls.route.hash = ''
  controls.restore.mockResolvedValue({ id: 7 })
  window.history.replaceState({}, '', '/auth/central/callback')
})
afterEach(() => {
  wrapper?.unmount()
})

// render mounts the actual callback with presentation-only layout and link substitutes.
async function render() {
  wrapper = mount(CentralCallbackView, {
    global: {
      stubs: {
        AuthLayout: { template: '<div><slot /></div>' },
        RouterLink: { template: '<a><slot /></a>' },
      },
    },
  })
  await flushPromises()
  return wrapper
}

describe('central authentication callback', () => {
  // A successful server callback has already installed its HttpOnly cookie.
  // The view restores metadata without parsing a bearer and then opens the product dashboard.
  it('restores only the cookie session before entering a protected page', async () => {
    await render()
    expect(controls.restore).toHaveBeenCalledOnce()
    expect(controls.replace).toHaveBeenCalledExactlyOnceWith('/dashboard')
    expect(localStorage.getItem('auth_token')).toBeNull()
  })

  // Unexpected credentials or redirect input must never reach session restoration.
  // They are removed from browser history and replaced with the fixed failure message.
  it.each(['code', 'access_token', 'state', 'redirect'])(
    'rejects unexpected %s without accepting browser credentials',
    async (parameter) => {
      controls.route.query = { [parameter]: 'must-not-be-used' }
      window.history.replaceState({}, '', `/auth/central/callback?${parameter}=must-not-be-used`)
      const view = await render()
      expect(controls.restore).not.toHaveBeenCalled()
      expect(controls.replace).not.toHaveBeenCalled()
      expect(window.location.search).toBe('?error=authentication_failed')
      expect(view.text()).toContain('auth.central.errors.authentication_failed')
    },
  )

  // Empty and duplicate error parameters are input even when their first value is falsy.
  // Neither case may restore an unrelated existing cookie as a successful callback.
  it.each([
    { error: '' },
    { error: null },
    { error: ['account_not_linked', 'access_denied'] },
    { error: 'untrusted-error' },
  ])('rejects malformed error input %j without session restoration', async ({ error }) => {
    controls.route.query = { error }
    const view = await render()
    expect(controls.restore).not.toHaveBeenCalled()
    expect(controls.replace).not.toHaveBeenCalled()
    expect(window.location.search).toBe('?error=authentication_failed')
    expect(view.text()).toContain('auth.central.errors.authentication_failed')
  })

  // A pending restoration rejects after the callback has already unmounted.
  // Its failure must not replace the history entry belonging to the next page.
  it('leaves later navigation untouched when an unmounted callback fails', async () => {
    const pending = Promise.withResolvers<{ id: number }>()
    controls.restore.mockReturnValueOnce(pending.promise)
    await render()
    wrapper?.unmount()
    window.history.replaceState({}, '', '/login?redirect=%2Fusage')
    pending.reject({ status: 503 })
    await flushPromises()
    expect(window.location.pathname).toBe('/login')
    expect(window.location.search).toBe('?redirect=%2Fusage')
    expect(controls.replace).not.toHaveBeenCalled()
  })

  // A fragment is never part of the backend callback contract, even alongside a valid error.
  // Cleanup removes it while retaining a fixed failure route for reload.
  it('rejects callback fragments and retains a fixed failure URL', async () => {
    controls.route.query = { error: 'account_not_linked' }
    controls.route.hash = '#access_token=must-not-be-used'
    window.history.replaceState(
      {},
      '',
      '/auth/central/callback?error=account_not_linked#access_token=must-not-be-used',
    )
    await render()
    expect(controls.restore).not.toHaveBeenCalled()
    expect(window.location.hash).toBe('')
    expect(window.location.search).toBe('?error=authentication_failed')
  })

  // An unbound identity requires an explicit product decision from the user.
  // The callback offers registration and existing-account login without creating or merging automatically.
  it('shows explicit recovery choices for an unlinked account', async () => {
    controls.route.query = { error: 'account_not_linked' }
    const view = await render()
    expect(controls.restore).not.toHaveBeenCalled()
    expect(view.text()).toContain('auth.central.errors.account_not_linked')
    expect(view.text()).toContain('auth.createAccount')
    expect(view.text()).toContain('auth.central.returnToLogin')
    expect(window.location.search).toBe('?error=account_not_linked')

    // Reload from the sanitized public error without retaining the earlier route object.
    // The usable session fixture must remain untouched by the failed flow.
    wrapper?.unmount()
    controls.route.query = Object.fromEntries(new URLSearchParams(window.location.search))
    const reloaded = await render()
    expect(controls.restore).not.toHaveBeenCalled()
    expect(controls.replace).not.toHaveBeenCalled()
    expect(reloaded.text()).toContain('auth.central.errors.account_not_linked')
  })
})
