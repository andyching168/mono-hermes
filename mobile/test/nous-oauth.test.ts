/**
 * Nous Portal OAuth login (flow B) on Android.
 *
 * The gateway's own rules are the specification here, so several tests pin them directly:
 * `_validate_loopback_redirect_uri` (hermes_cli/dashboard_auth/routes.py) accepts ONLY `http://` on
 * a canonical loopback IP literal, which is why a real loopback listener is required and why no
 * custom scheme / https App Link can be substituted.
 *
 * Covered: OAuth success, cancellation, state mismatch, token expiry, refresh-token rotation,
 * login resume, and a missing provider (plus the capability probe and redirect-URI parity checks).
 */
import { describe, expect, it } from 'vitest'

import {
  assertGatewayLoopbackRedirectUri,
  AuthSession,
  InvalidCredentialsError,
  isGatewayLoopbackRedirectUri,
  isOAuthCancellation,
  NeedsLoginError,
  NOUS_PROVIDER_NAME,
  NousProviderUnavailableError,
  nousOAuthLogin,
  OAUTH_LOOPBACK_PATH,
  OAuthCancelledError,
  type OAuthPlatform,
  probeServer,
  resolveNousOAuth,
  type ServerProbe,
  tokenNeedsRefresh
} from '../src/bridge/auth'
import { ConnectionStore, type TokenSet } from '../src/bridge/connection'
import type { HttpTransport, RawRequest, RawResponse } from '../src/bridge/http'
import { createMemoryStore, createPlainSecretBox } from '../src/bridge/storage'
import { s256Challenge } from '../src/bridge/util'

const LOOPBACK_PORT = 39117

const nousProbe: ServerProbe = {
  authRequired: true,
  baseUrl: 'http://100.64.1.2:9119',
  nativeFlow: true,
  providers: [{ displayName: 'Nous Research', name: 'nous', supportsPassword: false }],
  version: '0.21.5'
}

const TOKENS = { access_token: 'NOUS_AT', expires_at: 4102444800, provider: 'nous', refresh_token: 'NOUS_RT', user_id: 'portal-user' }

function scripted(handler: (req: RawRequest, seen: RawRequest[]) => Partial<RawResponse>) {
  const seen: RawRequest[] = []

  const transport: HttpTransport = {
    async request(req) {
      seen.push(req)

      return { body: '', headers: {}, setCookie: [], status: 200, ...handler(req, seen) }
    }
  }

  return { seen, transport }
}

/**
 * A stand-in for the native `OAuthLoopback` plugin + Custom Tab. It records whether the listener
 * and the browser tab were really cleaned up, and derives the callback URL from the authorize URL
 * the app actually opened (so `state` and PKCE are exercised for real, not faked).
 */
function scriptedPlatform(buildCallback: (authorize: URL, redirectUri: string) => string) {
  const events: string[] = []
  let browserClosed = false
  let listenerClosed = false
  let authorize: URL | null = null

  const platform: OAuthPlatform = {
    async openBrowser(url) {
      authorize = new URL(url)
      events.push('browser:open')

      return async () => {
        browserClosed = true
        events.push('browser:close')
      }
    },

    async openLoopback(path) {
      events.push('loopback:start')

      const redirectUri = `http://127.0.0.1:${LOOPBACK_PORT}${path}`

      return {
        async awaitCallback() {
          events.push('loopback:await')

          if (!authorize) {
            throw new Error('the browser was not opened before awaiting the callback')
          }

          return buildCallback(authorize, redirectUri)
        },
        async close() {
          listenerClosed = true
          events.push('loopback:close')
        },
        redirectUri
      }
    }
  }

  return {
    browserClosed: () => browserClosed,
    events,
    listenerClosed: () => listenerClosed,
    platform,
    authorizeUrl: () => authorize
  }
}

/** A callback that succeeds: echoes the app's own `state` and returns a code. */
const succeeds = (code = 'NOUS_CODE') => (authorize: URL) =>
  `${authorize.searchParams.get('redirect_uri')}?code=${code}&state=${authorize.searchParams.get('state')}`

describe('gateway redirect-URI parity', () => {
  it('accepts exactly what _validate_loopback_redirect_uri accepts', () => {
    expect(isGatewayLoopbackRedirectUri(`http://127.0.0.1:${LOOPBACK_PORT}${OAUTH_LOOPBACK_PATH}`)).toBe(true)
    expect(isGatewayLoopbackRedirectUri('http://127.0.0.1/hermes-mobile/oauth/callback')).toBe(true)
    expect(isGatewayLoopbackRedirectUri('http://[::1]:8080/cb')).toBe(true)
    // The desktop password flow's dead URI stays syntactically valid; it is just never fetched.
    expect(isGatewayLoopbackRedirectUri('http://127.0.0.1:47321/hermes-mobile/callback')).toBe(true)
  })

  it('refuses every redirect the gateway refuses (so no scheme can be invented)', () => {
    const rejected = [
      'com.hermesmovil.app://oauth/callback', // custom scheme
      'https://127.0.0.1:8080/cb', // not http
      'https://my-pc.tail1234.ts.net/auth/callback', // App Link
      'http://localhost:8080/cb', // localhost is explicitly refused by the gateway
      'http://127.0.0.1:8080/cb#fragment', // fragment
      'http://user@127.0.0.1:8080/cb', // userinfo
      'http://127.0.0.1:08080/cb', // non-canonical authority spelling
      'http://192.168.1.5:8080/cb', // not loopback
      'http://127.0.0.1:8080/cb\\x' // backslash
    ]

    for (const uri of rejected) {
      expect(isGatewayLoopbackRedirectUri(uri), uri).toBe(false)
    }

    // The gateway's validator preserves a query string, so parity means we accept one too.
    expect(isGatewayLoopbackRedirectUri('http://127.0.0.1:8080/cb?x=1')).toBe(true)

    expect(() => assertGatewayLoopbackRedirectUri('http://localhost:1/cb')).toThrow(/canonical loopback/)
  })
})

describe('capability detection via probeServer', () => {
  it('detects the nous provider and native_pkce from /api/status + /api/auth/providers', async () => {
    const { transport } = scripted(req => {
      const { pathname } = new URL(req.url)

      if (pathname === '/api/status') {
        return { body: JSON.stringify({ auth_flows: ['native_pkce'], auth_providers: ['nous'], auth_required: true, version: '0.21.5' }) }
      }

      return { body: JSON.stringify({ providers: [{ display_name: 'Nous Research', name: 'nous', supports_password: false }] }) }
    })

    const probe = await probeServer(transport, nousProbe.baseUrl)

    expect(probe.nativeFlow).toBe(true)
    expect(resolveNousOAuth(probe)).toEqual({ available: true })
  })

  it('reports a precise reason when the provider, the gated mode or native_pkce is missing', () => {
    const basicOnly: ServerProbe = {
      ...nousProbe,
      providers: [{ displayName: 'Username & Password', name: 'basic', supportsPassword: true }]
    }

    expect(resolveNousOAuth(basicOnly)).toEqual({ available: false, reason: expect.stringContaining('no "nous" provider') })
    expect(resolveNousOAuth({ ...nousProbe, nativeFlow: false }).available).toBe(false)
    expect(resolveNousOAuth({ ...basicOnly, nativeFlow: false }).available).toBe(false)
    expect(resolveNousOAuth({ ...nousProbe, authRequired: false }).available).toBe(false)

    // A provider that advertises password support is not an OAuth sign-in option.
    expect(resolveNousOAuth({ ...nousProbe, providers: [{ ...nousProbe.providers[0], supportsPassword: true }] }).available).toBe(false)
  })
})

describe('nousOAuthLogin', () => {
  it('binds a real loopback listener, opens the system browser, and binds PKCE to the code', async () => {
    const harness = scriptedPlatform(succeeds())
    const { seen, transport } = scripted(req =>
      new URL(req.url).pathname === '/auth/native/token' ? { body: JSON.stringify(TOKENS) } : {}
    )

    const tokens = await nousOAuthLogin(transport, nousProbe, { platform: harness.platform })

    expect(tokens).toMatchObject({ accessToken: 'NOUS_AT', provider: 'nous', refreshToken: 'NOUS_RT', userId: 'portal-user' })

    const opened = harness.authorizeUrl()!
    expect(opened.pathname).toBe('/auth/native/authorize')
    expect(opened.searchParams.get('provider')).toBe(NOUS_PROVIDER_NAME)
    expect(opened.searchParams.get('code_challenge_method')).toBe('S256')
    // The URI really is the listener's own ephemeral port, not the dead 47321 placeholder.
    expect(opened.searchParams.get('redirect_uri')).toBe(`http://127.0.0.1:${LOOPBACK_PORT}${OAUTH_LOOPBACK_PATH}`)

    // The verifier we redeem with must hash to the challenge the gateway was given.
    const tokenCall = seen.find(req => new URL(req.url).pathname === '/auth/native/token')!
    const verifier = (tokenCall.json as { code_verifier: string }).code_verifier

    expect((tokenCall.json as { code: string }).code).toBe('NOUS_CODE')
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(await s256Challenge(verifier)).toBe(opened.searchParams.get('code_challenge'))
    expect(opened.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{32}$/)

    // Cleanup is unconditional: the port must not outlive the flow.
    expect(harness.listenerClosed()).toBe(true)
    expect(harness.browserClosed()).toBe(true)
    expect(harness.events).toEqual(['loopback:start', 'browser:open', 'loopback:await', 'loopback:close', 'browser:close'])
  })

  it('treats an access_denied callback as a cancellation and never exchanges a code', async () => {
    const harness = scriptedPlatform(authorize => `${authorize.searchParams.get('redirect_uri')}?error=access_denied&state=${authorize.searchParams.get('state')}`)
    const { seen, transport } = scripted(() => ({ body: JSON.stringify(TOKENS) }))

    await expect(nousOAuthLogin(transport, nousProbe, { platform: harness.platform })).rejects.toBeInstanceOf(OAuthCancelledError)
    expect(seen).toEqual([])
    expect(harness.listenerClosed()).toBe(true)
    expect(harness.browserClosed()).toBe(true)
  })

  it('rejects a mismatched state as CSRF (not as a cancel) and never exchanges the code', async () => {
    const harness = scriptedPlatform(authorize => `${authorize.searchParams.get('redirect_uri')}?code=INJECTED&state=attacker-state`)
    const { seen, transport } = scripted(() => ({ body: JSON.stringify(TOKENS) }))

    const failure = await nousOAuthLogin(transport, nousProbe, { platform: harness.platform }).catch(error => error)

    expect(failure).not.toBeInstanceOf(OAuthCancelledError)
    expect(String(failure.message)).toMatch(/state mismatch/i)
    expect(seen).toEqual([])
    expect(harness.listenerClosed()).toBe(true)
  })

  it('refuses to start when the gateway has no nous provider (no listener is ever opened)', async () => {
    const harness = scriptedPlatform(succeeds())
    const { seen, transport } = scripted(() => ({ body: JSON.stringify(TOKENS) }))
    const basicOnly: ServerProbe = {
      ...nousProbe,
      providers: [{ displayName: 'Username & Password', name: 'basic', supportsPassword: true }]
    }

    await expect(nousOAuthLogin(transport, basicOnly, { platform: harness.platform })).rejects.toBeInstanceOf(NousProviderUnavailableError)

    expect(harness.events).toEqual([])
    expect(harness.authorizeUrl()).toBeNull()
    expect(seen).toEqual([])
  })

  it('surfaces a gateway token-exchange failure instead of storing a partial session', async () => {
    const harness = scriptedPlatform(succeeds())
    const { transport } = scripted(() => ({ body: '{"detail":"Invalid or expired authorization code."}', status: 400 }))

    await expect(nousOAuthLogin(transport, nousProbe, { platform: harness.platform })).rejects.toThrow(/Could not exchange the sign-in code/)

    expect(harness.listenerClosed()).toBe(true)
  })

  it('classifies only the authorization server error codes as cancellations', () => {
    expect(isOAuthCancellation(new OAuthCancelledError())).toBe(true)
    expect(isOAuthCancellation(new Error('Gateway rejected sign-in: access_denied (user said no)'))).toBe(true)
    expect(isOAuthCancellation(new Error('Sign-in response state mismatch (possible CSRF); try again.'))).toBe(false)
    expect(isOAuthCancellation(new Error('Could not exchange the sign-in code (400)'))).toBe(false)
  })
})

describe('AuthSession with a Nous OAuth session', () => {
  const statusBody = { auth_flows: ['native_pkce'], auth_providers: ['nous'], auth_required: true, version: '0.21.5' }

  async function session(tokens: Partial<TokenSet> = {}, refreshResponse?: Partial<RawResponse>) {
    const store = new ConnectionStore(createMemoryStore(), createPlainSecretBox())
    await store.setConnection({ baseUrl: nousProbe.baseUrl, provider: 'nous', username: '' })
    await store.setTokens({ accessToken: 'AT1', expiresAt: 0, provider: 'nous', refreshToken: 'RT1', userId: 'u', ...tokens })

    let refreshes = 0

    const { seen, transport } = scripted(req => {
      const { pathname } = new URL(req.url)

      if (pathname === '/api/status') {
        return { body: JSON.stringify(statusBody) }
      }

      refreshes += 1

      return refreshResponse ?? { body: JSON.stringify({ access_token: 'AT2', expires_at: 9999999999, refresh_token: 'RT2' }) }
    })

    return { auth: new AuthSession(store, transport, () => 1000), refreshes: () => refreshes, seen, store, transport }
  }

  it('persists the connection + tokens like a password login, and resumes them without re-authenticating', async () => {
    const store = new ConnectionStore(createMemoryStore(), createPlainSecretBox())
    const harness = scriptedPlatform(succeeds())

    const loginTransport: HttpTransport = {
      async request(req) {
        const { pathname } = new URL(req.url)

        if (pathname === '/api/status') {
          return { body: JSON.stringify(statusBody), headers: {}, setCookie: [], status: 200 }
        }

        if (pathname === '/api/auth/providers') {
          return { body: JSON.stringify({ providers: [{ name: 'nous', supports_password: false }] }), headers: {}, setCookie: [], status: 200 }
        }

        return { body: JSON.stringify(TOKENS), headers: {}, setCookie: [], status: 200 }
      }
    }

    const probe = await new AuthSession(store, loginTransport).loginWithNous(nousProbe.baseUrl, { platform: harness.platform })

    expect(probe.nativeFlow).toBe(true)
    expect(await store.getConnection()).toMatchObject({ baseUrl: nousProbe.baseUrl, provider: 'nous' })
    expect(await store.getTokens()).toMatchObject({ accessToken: 'NOUS_AT', refreshToken: 'NOUS_RT', provider: 'nous' })

    // Resume: a fresh AuthSession over the same store needs no browser and no OAuth round trip.
    const calls: string[] = []

    const resumeTransport: HttpTransport = {
      async request(req) {
        calls.push(new URL(req.url).pathname)

        return { body: '', headers: {}, setCookie: [], status: 200 }
      }
    }

    const resumed = new AuthSession(store, resumeTransport)

    expect(await resumed.accessToken()).toBe('NOUS_AT')
    expect(calls).toEqual([])
    expect(harness.events).toEqual(['loopback:start', 'browser:open', 'loopback:await', 'loopback:close', 'browser:close'])
  })

  it('refreshes an expired token and rotates the stored refresh token', async () => {
    const { auth, refreshes, store } = await session({ expiresAt: 900 })

    expect(tokenNeedsRefresh({ expiresAt: 900 }, 1000)).toBe(true)
    expect(await auth.accessToken()).toBe('AT2')
    expect(refreshes()).toBe(1)
    expect(await store.getTokens()).toMatchObject({ accessToken: 'AT2', provider: 'nous', refreshToken: 'RT2' })
  })

  it('shares one rotation between concurrent callers (the gateway revokes on reuse)', async () => {
    const { auth, refreshes } = await session({ expiresAt: 900 })

    const tokens = await Promise.all([auth.accessToken(), auth.accessToken(), auth.accessToken()])

    expect(tokens).toEqual(['AT2', 'AT2', 'AT2'])
    expect(refreshes()).toBe(1)
  })

  it('signs out and asks for a new login when the refresh token is rejected', async () => {
    const { auth, store } = await session({ expiresAt: 900 }, { body: '{"error":"session_expired"}', status: 401 })

    await expect(auth.accessToken()).rejects.toBeInstanceOf(NeedsLoginError)
    expect(await store.getTokens()).toBeNull()
  })

  it('keeps the OAuth session on a transient provider outage', async () => {
    const { auth, store } = await session({ expiresAt: 900 }, { status: 503 })

    await expect(auth.accessToken()).rejects.toThrow(/^503/)
    expect((await store.getTokens())?.refreshToken).toBe('RT1')
  })

  it('retries once with a rotated bearer after a 401, then asks for a new login', async () => {
    const { auth, seen } = await session({ expiresAt: 9999999999 }, { body: JSON.stringify({ access_token: 'AT2', expires_at: 9999999999, refresh_token: 'RT2' }) })

    const attempts: string[] = []

    const result = await auth.withBearer(async token => {
      attempts.push(token)

      if (attempts.length === 1) {
        const { HttpStatusError } = await import('../src/bridge/http')

        throw new HttpStatusError(401, 'nope')
      }

      return 'ok'
    })

    expect(result).toBe('ok')
    expect(attempts).toEqual(['AT1', 'AT2'])
    expect(seen.some(req => new URL(req.url).pathname === '/auth/native/refresh')).toBe(true)
  })

  it('keeps Basic Auth working unchanged alongside the OAuth path', async () => {
    // The `basic` provider still resolves as a password option and never as a Nous one.
    const basicProbe: ServerProbe = {
      ...nousProbe,
      providers: [
        { displayName: 'Nous Research', name: 'nous', supportsPassword: false },
        { displayName: 'Username & Password', name: 'basic', supportsPassword: true }
      ]
    }

    expect(resolveNousOAuth(basicProbe).available).toBe(true)
    expect(basicProbe.providers.filter(p => p.supportsPassword).map(p => p.name)).toEqual(['basic'])

    const store = new ConnectionStore(createMemoryStore(), createPlainSecretBox())
    let state = ''
    let authorized = false

    const { transport } = scripted(req => {
      const { pathname, searchParams } = new URL(req.url)

      if (pathname === '/api/status') {
        return { body: JSON.stringify({ auth_flows: ['native_pkce'], auth_providers: ['basic', 'nous'], auth_required: true, version: '0.21.5' }) }
      }

      if (pathname === '/auth/native/authorize') {
        state = searchParams.get('state')!
        authorized = true

        return { headers: { location: '/login' }, setCookie: ['hermes_session_pkce=h; Path=/'], status: 302 }
      }

      if (pathname === '/auth/password-login') {
        // The password flow's redirect target is only ever parsed, never fetched.
        return { body: JSON.stringify({ next: `http://127.0.0.1:47321/hermes-mobile/callback?code=GW&state=${state}`, ok: true }) }
      }

      return { body: JSON.stringify({ access_token: 'BASIC_AT', expires_at: 4102444800, provider: 'basic', refresh_token: 'BASIC_RT', user_id: 'u' }) }
    })

    const tokens = await new AuthSession(store, transport).login(nousProbe.baseUrl, { password: 'p', username: 'u' })

    expect(authorized).toBe(true)
    expect(await store.getTokens()).toMatchObject({ accessToken: 'BASIC_AT', provider: 'basic' })
    expect((await store.getConnection())?.provider).toBe('basic')
  })

  it('still reports invalid credentials through the password path', async () => {
    const { transport } = scripted(req => {
      const { pathname } = new URL(req.url)

      if (pathname === '/api/status') {
        return { body: JSON.stringify({ auth_flows: ['native_pkce'], auth_providers: ['basic'], auth_required: true, version: '0.21.5' }) }
      }

      return pathname === '/auth/native/authorize'
        ? { headers: { location: '/login' }, setCookie: ['hermes_session_pkce=h'], status: 302 }
        : { status: 401 }
    })

    const store = new ConnectionStore(createMemoryStore(), createPlainSecretBox())

    await expect(
      new AuthSession(store, transport).login(nousProbe.baseUrl, { password: 'bad', username: 'u' })
    ).rejects.toBeInstanceOf(InvalidCredentialsError)
  })
})
