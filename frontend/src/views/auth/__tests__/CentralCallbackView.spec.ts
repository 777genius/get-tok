import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import CentralCallbackView from '@/views/auth/CentralCallbackView.vue'

// CentralCallbackView.spec.ts checks the credential-free callback boundary and its
// fixed recovery choices. The production view handles route input and navigation while
// a controlled session endpoint isolates URL rejection from backend token qualification.

// The route fixture supplies only navigation inputs; session restoration and destination
// changes remain independently observable so rejected callbacks cannot appear successful.
const controls = vi.hoisted(() => ({
  route: { query: {} as Record<string, string>, hash: '' }, // Current callback location inputs.
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
      expect(window.location.search).toBe('')
      expect(view.text()).toContain('auth.central.errors.authentication_failed')
    },
  )

  // An unbound identity requires an explicit product decision from the user.
  // The callback offers registration and existing-account login without creating or merging automatically.
  it('shows explicit recovery choices for an unlinked account', async () => {
    controls.route.query = { error: 'account_not_linked' }
    const view = await render()
    expect(controls.restore).not.toHaveBeenCalled()
    expect(view.text()).toContain('auth.central.errors.account_not_linked')
    expect(view.text()).toContain('auth.createAccount')
    expect(view.text()).toContain('auth.central.returnToLogin')
  })
})
