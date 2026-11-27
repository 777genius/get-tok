import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { chromium } from 'playwright'

// test-central-browser.mjs qualifies the built GetTok authentication interface against
// the real loopback BFF, Keycloak, Identity service, and PostgreSQL fixture. The browser
// obtains its own cookie through the rendered sign-in flow; no provider response,
// authentication endpoint, or cookie is mocked or injected by this runner.
//
// The surrounding Go fixture creates the product account before browser login and
// later exercises central suspension with its separate session. This runner verifies
// the frontend callback, memory-only authentication, restoration after reload, CSRF
// rejection, and confirmed logout. Reports contain bounded outcomes and browser versions,
// never authorization codes, cookie values, CSRF proofs, passwords, or provider tokens.

// required reads one explicit native prerequisite without including its value in errors.
function required(name) {
  const value = process.env[name]
  assert.ok(typeof value === 'string' && value.length > 0, `Native browser requires ${name}`)
  return value
}

// Native browser inputs are restricted to the disposable fixture's exact origins.
// Production credentials and arbitrary redirect destinations are outside this runner's scope.
const origin = required('GETTOK_NATIVE_ORIGIN') // Real GetTok fixture origin.
const issuer = required('IDENTITY_TEST_ISSUER') // Real Keycloak fixture issuer.
const password = required('IDENTITY_TEST_USER_PASSWORD') // Disposable upstream user credential.
assert.equal(origin, 'http://127.0.0.1:18182')
assert.equal(issuer, 'http://127.0.0.1:18080/realms/identity-test')
const expectedNode = (
  await readFile(new URL('../../.node-version', import.meta.url), 'utf8')
).trim()
assert.equal(process.versions.node, expectedNode.replace(/^v/, ''))
const dependency = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
const installed = JSON.parse(
  await readFile(new URL('../node_modules/playwright/package.json', import.meta.url), 'utf8'),
)
assert.equal(installed.version, dependency.devDependencies.playwright)
// Capture only rendered product pages whose address is free of authentication
// parameters. Provider pages, traces, and network payloads are never captured here.
const screenshots =
  process.env.GETTOK_NATIVE_SCREENSHOT_DIR || (await mkdtemp(join(tmpdir(), 'gettok-browser-')))
assert.ok(isAbsolute(screenshots), 'Native screenshot directory must be absolute')
await mkdir(screenshots, { recursive: true })

// Phase names expose a useful failure boundary without retaining sensitive page URLs.
// The process owns one browser and closes it during success, failure, or interruption.
let phase = 'launch' // Current bounded qualification phase.
let browser // Owned native browser process.
let interrupted = false // Native cancellation observation flag.

// interrupt closes the owned browser before a cancelled parent stops waiting for it.
// Playwright operations then reject and the normal failure path reports cancellation.
// Repeated close calls are safe and do not authorize any remaining browser action.
async function interrupt() {
  interrupted = true
  await browser?.close()
}
process.once('SIGINT', interrupt)
process.once('SIGTERM', interrupt)

// verifyStorage checks persistence from the harness without injecting the HttpOnly secret.
// Browser JavaScript supplies its observable storage only; comparisons with the opaque
// cookie happen in Node, so the test does not itself expose that credential to the page.
async function verifyStorage(page, session, cookie) {
  const visible = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    cookie: document.cookie,
    query: location.search,
    fragment: location.hash,
  }))
  const forbidden = ['auth_token', 'refresh_token', 'auth_user', 'token_expires_at', 'csrf_token']
  assert.ok(
    !visible.local.some(([key]) => forbidden.includes(key)),
    'Central authentication must not use legacy persistent keys',
  )
  assert.ok(
    !visible.session.some(([key]) => forbidden.includes(key)),
    'Central authentication must not use session storage credentials',
  )
  const persisted = JSON.stringify([visible.local, visible.session])
  assert.ok(!persisted.includes(session.csrf_token), 'CSRF proof must remain in memory')
  assert.ok(
    !persisted.includes(cookie.value),
    'Opaque authentication must not enter browser storage',
  )
  assert.ok(
    !visible.cookie.includes('gettok-central-test='),
    'The authentication cookie must remain HttpOnly',
  )
  assert.equal(visible.query, '')
  assert.equal(visible.fragment, '')
}

try {
  browser = await chromium.launch({
    headless: true,
    executablePath: process.env.GETTOK_NATIVE_BROWSER_EXECUTABLE || undefined,
  })
  const context = await browser.newContext({ locale: 'en-US' })
  const page = await context.newPage()
  page.setDefaultTimeout(15_000)
  const pageErrors = [] // Unhandled page exceptions, without their potentially sensitive text.
  const frontendCallbacks = [] // Actual document destinations observed before SPA cleanup.
  page.on('pageerror', () => {
    pageErrors.push('page-error')
  })
  page.on('framenavigated', (frame) => {
    if (frame !== page.mainFrame()) return
    const destination = new URL(frame.url())
    if (destination.pathname === '/auth/central/callback') {
      frontendCallbacks.push(destination.href)
    }
  })

  phase = 'rendered-login'
  await page.goto(`${origin}/login`, { waitUntil: 'domcontentloaded' })
  await page
    .getByRole('button', { name: 'Sign in with Agent Teams TEST', exact: true })
    .waitFor({ state: 'visible' })
  await page.screenshot({ path: join(screenshots, 'gettok-central-login.png'), fullPage: true })
  await page.getByRole('button', { name: 'Sign in with Agent Teams TEST', exact: true }).click()
  await page.locator('#username').waitFor({ state: 'visible' })
  const providerLocation = new URL(page.url())
  assert.ok(
    providerLocation.origin === new URL(issuer).origin &&
      providerLocation.pathname.startsWith('/realms/identity-test/'),
    'Credentials may be entered only at the pinned test provider',
  )

  phase = 'provider-and-callback'
  await page.locator('#username').fill('fixture-gettok')
  await page.locator('#password').fill(password)
  const bootstrapped = page.waitForResponse(
    (response) =>
      new URL(response.url()).origin === origin &&
      new URL(response.url()).pathname === '/api/v1/auth/central/session' &&
      response.status() === 200,
  )
  await page.locator('#kc-login').click()
  const response = await bootstrapped
  const envelope = await response.json()
  assert.equal(envelope.code, 0)
  const session = envelope.data
  assert.equal(session.auth_mode, 'central')
  assert.ok(session.user.id > 0 && session.csrf_token.length > 0)
  assert.ok(!['access_token', 'refresh_token', 'id_token'].some((key) => key in session))
  assert.ok(
    frontendCallbacks.length > 0 &&
      frontendCallbacks.every((destination) => destination === `${origin}/auth/central/callback`),
    'The actual frontend callback must have the exact origin and no credentials or fragment',
  )
  await page.waitForURL((url) => url.origin === origin && url.pathname === '/dashboard')
  const cookie = (await context.cookies(origin)).find(
    (value) => value.name === 'gettok-central-test',
  )
  assert.ok(cookie?.httpOnly && cookie.sameSite === 'Lax' && cookie.path === '/')
  assert.ok(cookie.expires > 0, 'Central authentication requires an explicit cookie expiry')
  assert.ok(cookie.expires * 1000 <= Date.parse(session.expires_at) + 1000)
  await verifyStorage(page, session, cookie)
  await page.getByRole('button', { name: 'User menu', exact: true }).waitFor({ state: 'visible' })
  await page.screenshot({ path: join(screenshots, 'gettok-central-session.png'), fullPage: true })

  phase = 'protected-profile-and-csrf'
  const profile = await context.request.get(`${origin}/api/v1/auth/me`, {
    headers: { 'X-CSRF-Token': session.csrf_token },
  })
  assert.equal(profile.status(), 200)
  const identity = await profile.json()
  assert.equal(identity.data.id, session.user.id)
  assert.equal(identity.data.balance, 17)
  for (const headers of [{}, { 'X-CSRF-Token': 'incorrect-session-proof' }]) {
    const status = await page.evaluate(async (requestHeaders) => {
      const result = await fetch('/api/v1/auth/central/logout', {
        method: 'POST',
        headers: requestHeaders,
        credentials: 'include',
      })
      await result.arrayBuffer()
      return result.status
    }, headers)
    assert.equal(status, 403)
  }
  const mismatchedRead = await context.request.get(`${origin}/api/v1/auth/me`, {
    headers: { 'X-CSRF-Token': 'another-tab-session-proof' },
  })
  assert.equal(mismatchedRead.status(), 403)
  // Another tab can replace a shared cookie while this document retains a legacy
  // view. Protected reads must require the document's matching session proof too.
  const unboundRead = await context.request.get(`${origin}/api/v1/auth/me`)
  assert.equal(unboundRead.status(), 403)

  phase = 'reload-restoration'
  const restored = page.waitForResponse(
    (value) =>
      new URL(value.url()).pathname === '/api/v1/auth/central/session' && value.status() === 200,
  )
  await page.reload({ waitUntil: 'domcontentloaded' })
  const restoredBody = await (await restored).json()
  assert.equal(restoredBody.data.user.id, session.user.id)
  assert.equal(restoredBody.data.expires_at, session.expires_at)
  await page.getByRole('button', { name: 'User menu', exact: true }).waitFor({ state: 'visible' })
  await verifyStorage(page, restoredBody.data, cookie)

  phase = 'confirmed-logout'
  const revoked = page.waitForResponse(
    (value) =>
      new URL(value.url()).pathname === '/api/v1/auth/central/logout' &&
      value.request().method() === 'POST' &&
      value.status() === 200,
  )
  await page.getByRole('button', { name: 'User menu', exact: true }).click()
  await page.getByRole('button', { name: 'Logout', exact: true }).click()
  await revoked
  await page.waitForURL((url) => url.origin === origin && url.pathname === '/login')
  const denied = await context.request.get(`${origin}/api/v1/auth/me`)
  assert.equal(denied.status(), 401)
  assert.equal(
    pageErrors.length,
    0,
    'The actual authentication interface must not throw unhandled errors',
  )
  assert.equal(interrupted, false)
  process.stdout.write(
    `${JSON.stringify({
      nativeGetTokBrowser: 'passed',
      browser: browser.version(),
      playwright: installed.version,
      renderedLogin: true,
      callbackWithoutCredentials: true,
      cookieHttpOnly: true,
      memoryOnlySession: true,
      csrfRejected: true,
      reloadPreservesDeadline: true,
      logoutRevoked: true,
      independentContinuity: 'not-admitted',
    })}\n`,
  )
} catch {
  process.stderr.write(`${JSON.stringify({ nativeGetTokBrowser: 'failed', phase, interrupted })}\n`)
  process.exitCode = 1
} finally {
  await browser?.close()
  process.removeListener('SIGINT', interrupt)
  process.removeListener('SIGTERM', interrupt)
}
