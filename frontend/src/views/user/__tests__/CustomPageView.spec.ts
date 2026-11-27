import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { ref } from 'vue'
import { replaceAuthentication } from '@/api/authenticationContext'
import CustomPageView from '../CustomPageView.vue'

// CustomPageView.spec.ts checks which asynchronous Markdown request may publish
// article content or errors. The actual component renders controlled response bodies
// while locale and authentication changes reproduce older requests completing after
// a newer article, independently of server availability or application shell behavior.

// The test locale drives the component's real watcher, while each mounted view owns
// its current request generation and is disposed before the next fixture begins.
const locale = ref('en')
let wrapper: VueWrapper | undefined

vi.mock('vue-router', () => ({ useRoute: () => ({ params: { id: 'fixture-page' } }) }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ locale, t: (key: string) => key }) }))
vi.mock('@/stores', () => ({
  useAppStore: () => ({
    publicSettingsLoaded: true,
    cachedPublicSettings: {
      custom_menu_items: [{ id: 'fixture-page', label: 'Fixture', page_slug: 'fixture', url: '' }],
    },
  }),
}))
vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({ isAdmin: false, user: null, token: null }),
}))
vi.mock('@/stores/adminSettings', () => ({
  useAdminSettingsStore: () => ({ customMenuItems: [] }),
}))
vi.mock('@/api/client', () => ({ buildApiUrl: (path: string) => `/api/v1${path}` }))
vi.mock('@/components/layout/AppLayout.vue', () => ({
  default: { template: '<main><slot /></main>' },
}))
vi.mock('@/components/common/MotionTransition.vue', () => ({
  default: { template: '<div><slot /></div>' },
}))

beforeEach(() => {
  locale.value = 'en'
  replaceAuthentication()
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  replaceAuthentication()
  vi.unstubAllGlobals()
})

// pendingMarkdown holds a real response at its asynchronous body boundary.
// Tests explicitly resolve or reject that body after dispatch, so the component
// observes authentication and request ownership changes through its normal awaits.
function pendingMarkdown() {
  let resolve!: (value: string) => void
  let reject!: (reason: Error) => void
  const body = new Promise<string>((resolveBody, rejectBody) => {
    resolve = resolveBody
    reject = rejectBody
  })
  const response = new Response('')
  const text = vi.spyOn(response, 'text').mockReturnValue(body)
  return { response, text, resolve, reject }
}

describe('Markdown request ownership', () => {
  // An older body completes after a new locale has already rendered replacement content.
  // Both an epoch rejection and a failed old body must preserve that newer article.
  it.each(['replaced-session', 'failed-body'])(
    'retains the newer article after %s from an older request',
    async (outcome) => {
      const old = pendingMarkdown()
      const fetch = vi
        .fn()
        .mockResolvedValueOnce(old.response)
        .mockResolvedValueOnce(new Response('# New article'))
      vi.stubGlobal('fetch', fetch)
      wrapper = mount(CustomPageView)
      await flushPromises()
      expect(old.text).toHaveBeenCalledTimes(1)

      if (outcome === 'replaced-session') replaceAuthentication()
      locale.value = 'ru'
      await flushPromises()
      expect(fetch).toHaveBeenCalledTimes(2)
      expect(wrapper.find('.markdown-page-content').text()).toContain('New article')

      if (outcome === 'replaced-session') old.resolve('# Old article')
      else old.reject(new Error('Old body failed'))
      await flushPromises()
      expect(wrapper.find('.markdown-page-content').text()).toContain('New article')
      expect(wrapper.text()).not.toContain('customPage.markdownLoadFailed')
    },
  )

  // A body fails without a newer locale request, while authentication either stays or changes.
  // Only the same session may publish the current request's translated load error.
  it.each([false, true])(
    'publishes a current failure only for replacement=%s',
    async (replaced) => {
      const pending = pendingMarkdown()
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(pending.response))
      wrapper = mount(CustomPageView)
      await flushPromises()
      expect(pending.text).toHaveBeenCalledTimes(1)
      if (replaced) replaceAuthentication()
      pending.reject(new Error('Body failed'))
      await flushPromises()
      expect(wrapper.text().includes('customPage.markdownLoadFailed')).toBe(!replaced)
    },
  )
})
