/**
 * Native (RFC 8252 style) bearer login against a gated `hermes serve` gateway.
 *
 * Two login methods share one token layer:
 *
 *   A. Username & password (the `basic` provider) - no browser needed. Desktop opens
 *      the system browser and runs a loopback listener; a phone cannot do either, but
 *      the gateway's broker makes that unnecessary for password providers:
 *
 *   1. GET  /auth/native/authorize?provider=..&code_challenge=..&redirect_uri=<loopback>&state=..
 *        -> 302 /login + a PKCE cookie holding the server-side broker handle
 *   2. POST /auth/password-login {provider, username, password}   (cookie attached)
 *        -> {ok, next}; `next` is the loopback redirect carrying ?code=..&state=..
 *           (never followed - we only read code/state out of it)
 *   3. POST /auth/native/token {code, code_verifier}  -> {access_token, refresh_token, expires_at}
 *   4. POST /auth/native/refresh {refresh_token, provider} rotates the pair.
 *
 *      Step 2 is why this flow can get away with a loopback URI nothing listens on: the
 *      gateway *returns* that URL inside a JSON body, so `next` can simply be parsed. See
 *      NATIVE_REDIRECT_URI.
 *
 *   B. Nous Portal OAuth (the `nous` provider) - needs a real browser AND a real listener,
 *      because now the gateway 302s the *system browser* to the redirect URI:
 *
 *   1. Bind a loopback socket (native `OAuthLoopback` plugin) -> http://127.0.0.1:<port>/...
 *   2. Open the authorize URL in the system browser / Custom Tab (never a WebView we control,
 *      so the Portal credentials are typed into the real browser).
 *   3. The gateway brokers to Portal, then 302s the browser back to the loopback URI with
 *      ?code=..&state=..; the listener captures it and the tab is closed.
 *   4. Steps 3-4 above (token exchange + refresh) are shared verbatim with flow A.
 *
 * The gateway is the authority on what redirect URI it will accept: it must be `http://` on a
 * canonical loopback IP literal. `isGatewayLoopbackRedirectUri` below mirrors that rule, and no
 * custom scheme or https App Link can be substituted for it.
 *
 * The cookie only has to survive between step 1 and 2, so a tiny in-memory jar
 * is enough and no browser session cookie is ever stored. REST then uses
 * `Authorization: Bearer`, and WebSockets use single-use tickets (gateway-ws.ts).
 *
 * Mirrors electron/native-oauth.ts + native-auth-decisions.ts; the pure helpers
 * keep the same names so upstream drift is easy to diff.
 */

import { type ConnectionStore, type TokenSet } from './connection'
import { CookieJar, type HttpTransport, HttpStatusError, type RawResponse } from './http'
import {
  assertTransportAllowed,
  errorMessage,
  isLanCleartext,
  normalizeBaseUrl,
  randomBase64url,
  s256Challenge,
  type TransportPolicyOptions
} from './util'

/**
 * Syntactically valid loopback redirect for the PASSWORD broker flow; nothing listens on it and it
 * is never fetched, because `POST /auth/password-login` returns it in JSON and we only parse
 * `code`/`state` out of it.
 *
 * It is NOT usable for OAuth: there the gateway 302s the system browser to this exact URI, so a
 * listener must really exist. `isGatewayLoopbackRedirectUri` accepts its syntax, but only the
 * native `OAuthLoopback` plugin's own ephemeral `redirectUri` may be used for flow B.
 */
export const NATIVE_REDIRECT_URI = 'http://127.0.0.1:47321/hermes-mobile/callback'

/** Provider name the Nous Portal plugin registers under (plugins/dashboard_auth/nous). */
export const NOUS_PROVIDER_NAME = 'nous'

/** Loopback path our OAuth listener answers on. The gateway constrains the authority, not the path. */
export const OAUTH_LOOPBACK_PATH = '/hermes-mobile/oauth/callback'

/** The gateway drops a pending native authorization after 600 s; stay comfortably inside that. */
export const OAUTH_CALLBACK_TIMEOUT_MS = 300_000

const PASSWORD_PROVIDER_NAMES = new Set(['basic'])

export interface AuthProviderInfo {
  name: string
  displayName: string
  supportsPassword: boolean
}

export interface ServerProbe {
  baseUrl: string
  version: string | null
  authRequired: boolean
  nativeFlow: boolean
  providers: AuthProviderInfo[]
}

/** Raised whenever the user has to type credentials again. Carries the flags the renderer keys on. */
export class NeedsLoginError extends Error {
  readonly needsOauthLogin = true
  readonly statusCode = 401

  constructor(message = 'Your session has expired. Sign in again.') {
    super(message)
    this.name = 'NeedsLoginError'
  }
}

export class InvalidCredentialsError extends Error {
  constructor(message = 'Invalid username or password.') {
    super(message)
    this.name = 'InvalidCredentialsError'
  }
}

/** The gateway does not offer a `nous` provider (or is not gated / lacks native_pkce). */
export class NousProviderUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NousProviderUnavailableError'
  }
}

/** The user backed out of the browser (or the authorization server refused silently). */
export class OAuthCancelledError extends Error {
  constructor(message = 'Sign-in was cancelled.') {
    super(message)
    this.name = 'OAuthCancelledError'
  }
}

export function normalizeProviders(raw: unknown): AuthProviderInfo[] {
  if (!Array.isArray(raw)) {
    return []
  }

  const out: AuthProviderInfo[] = []

  for (const item of raw) {
    if (typeof item === 'string' && item.trim()) {
      out.push({
        displayName: item.trim(),
        name: item.trim(),
        supportsPassword: PASSWORD_PROVIDER_NAMES.has(item.trim())
      })

      continue
    }

    if (item && typeof item === 'object') {
      const record = item as Record<string, unknown>
      const name = typeof record.name === 'string' ? record.name.trim() : ''

      if (name) {
        out.push({
          displayName: typeof record.display_name === 'string' ? record.display_name : name,
          name,
          supportsPassword:
            typeof record.supports_password === 'boolean'
              ? record.supports_password
              : PASSWORD_PROVIDER_NAMES.has(name)
        })
      }
    }
  }

  return out
}

function parseJson(text: string): any {
  try {
    return text ? JSON.parse(text) : null
  } catch {
    return null
  }
}

function describeFailure(response: RawResponse, fallback: string): string {
  const body = parseJson(response.body)
  const detail = typeof body?.detail === 'string' ? body.detail : typeof body?.error === 'string' ? body.error : ''

  return `${fallback} (${response.status}${detail ? `: ${detail}` : ''})`
}

/** Public, credential-free reachability + capability probe (/api/status, /api/auth/providers). */
export async function probeServer(
  transport: HttpTransport,
  rawUrl: string,
  policy: TransportPolicyOptions = {}
): Promise<ServerProbe> {
  const baseUrl = normalizeBaseUrl(rawUrl)
  assertTransportAllowed(baseUrl, policy)

  let status: RawResponse

  try {
    status = await transport.request({ timeoutMs: 8_000, url: `${baseUrl}/api/status` })
  } catch (error) {
    throw new Error(`Could not reach ${baseUrl}. Is Tailscale connected and "hermes serve" running? (${errorMessage(error)})`)
  }

  const body = parseJson(status.body)

  if (status.status >= 400 || !body || typeof body !== 'object' || /^\s*</.test(status.body)) {
    throw new Error(
      `${baseUrl} answered ${status.status} but does not look like a Hermes gateway (expected JSON from /api/status).`
    )
  }

  const authRequired = Boolean(body.auth_required)
  const flows: unknown = body.auth_flows
  let providers = normalizeProviders(body.auth_providers)

  if (authRequired) {
    try {
      const response = await transport.request({ timeoutMs: 8_000, url: `${baseUrl}/api/auth/providers` })

      if (response.status < 400) {
        const detailed = normalizeProviders(parseJson(response.body)?.providers)

        if (detailed.length > 0) {
          providers = detailed
        }
      }
    } catch {
      // /api/status already named the providers; the detailed list is best-effort.
    }
  }

  return {
    authRequired,
    baseUrl,
    nativeFlow: Array.isArray(flows) && flows.includes('native_pkce'),
    providers,
    version: typeof body.version === 'string' ? body.version : null
  }
}

/** Case-insensitive provider lookup on a probe result. */
export function findAuthProvider(probe: ServerProbe, name: string): AuthProviderInfo | null {
  const wanted = name.trim().toLowerCase()

  return probe.providers.find(provider => provider.name.toLowerCase() === wanted) ?? null
}

export type NousOAuthDecision = { available: true } | { available: false; reason: string }

/**
 * Decide whether Nous Portal sign-in is offered, and say precisely why not when it is not.
 *
 * Mirrors upstream `resolveLoginStrategy`: the native flow needs `native_pkce` on /api/status AND a
 * non-password provider, and `oauthGuardMayHardFail` treats "all providers are password-based" as
 * "this gateway does not speak OAuth". The `nous` provider only registers when the operator
 * configured `dashboard.oauth.client_id` / `HERMES_DASHBOARD_OAUTH_CLIENT_ID`, so a gateway that
 * only has `basic` legitimately has no Portal sign-in to offer.
 */
export function resolveNousOAuth(probe: ServerProbe): NousOAuthDecision {
  if (!probe.authRequired) {
    return { available: false, reason: 'This Hermes server is not running in gated mode, so there is nothing to sign in to.' }
  }

  if (!probe.nativeFlow) {
    return {
      available: false,
      reason:
        'This Hermes server does not advertise the native_pkce flow. Update Hermes on the PC (hermes update) and restart "hermes serve".'
    }
  }

  const nous = findAuthProvider(probe, NOUS_PROVIDER_NAME)

  if (!nous || nous.supportsPassword) {
    return {
      available: false,
      reason:
        'This Hermes server does not offer Nous Portal sign-in (no "nous" provider). ' +
        'Set dashboard.oauth.client_id on the PC, or sign in with username & password.'
    }
  }

  return { available: true }
}

/**
 * Loopback hosts the gateway accepts, spelled exactly as `_validate_loopback_redirect_uri`
 * requires. Keyed by WHATWG `URL.hostname`, which reports an IPv6 literal *with* its brackets.
 */
const GATEWAY_LOOPBACK_AUTHORITIES: Record<string, string> = { '127.0.0.1': '127.0.0.1', '[::1]': '[::1]' }

/**
 * Gate a redirect URI through the same rules the gateway applies in
 * `_validate_loopback_redirect_uri` (hermes_cli/dashboard_auth/routes.py):
 *
 *   - ASCII printable only (no controls, no space, no backslash)
 *   - scheme exactly `http` - so a custom scheme like `com.hermesmovil.app://oauth` can never be
 *     registered as a workaround
 *   - host a loopback IP literal spelled canonically (`localhost` is explicitly refused, and so is
 *     every `https://` App Link)
 *   - no fragment, no userinfo, canonical authority spelling (`:00080` or an upper-case host would
 *     be a 400). A query string IS preserved by the gateway, so we accept one too.
 *
 * Checked before the browser is opened, so a misconfigured listener fails locally with a clear
 * message instead of bouncing the user to an opaque gateway 400.
 */
export function isGatewayLoopbackRedirectUri(raw: string): boolean {
  if (!raw || !/^[\x21-\x7e]+$/.test(raw) || raw.includes('\\') || raw.includes('#')) {
    return false
  }

  let parsed: URL

  try {
    parsed = new URL(raw)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' || parsed.username || parsed.password || !parsed.pathname.startsWith('/')) {
    return false
  }

  const canonicalHost = GATEWAY_LOOPBACK_AUTHORITIES[parsed.hostname]

  if (!canonicalHost) {
    return false
  }

  const canonicalAuthority = parsed.port ? `${canonicalHost}:${parsed.port}` : canonicalHost

  // Compare the *raw* authority too: the URL parser would silently canonicalise ":00080", both of
  // which the gateway rejects (it compares `parsed.netloc` against its canonical spelling).
  const rawAuthority = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[/?#]/, 1)[0]

  return rawAuthority === canonicalAuthority
}

export function assertGatewayLoopbackRedirectUri(raw: string): string {
  if (!isGatewayLoopbackRedirectUri(raw)) {
    throw new Error(
      `The Hermes gateway only accepts a canonical loopback redirect URI (http://127.0.0.1:<port>/...), got ${raw || 'nothing'}.`
    )
  }

  return raw
}

/**
 * The Android side of the OAuth login, injected so the flow is testable without a device.
 * Production uses `oauthPlatform` in native-oauth.ts (Custom Tab + the native `OAuthLoopback`
 * plugin).
 */
export interface OAuthLoopbackHandle {
  /** Canonical `http://127.0.0.1:<port><path>` the gateway will send the browser back to. */
  redirectUri: string
  /** Raw request target the browser asked for; rejects with {@link OAuthCancelledError} on cancel. */
  awaitCallback(): Promise<string>
  close(): Promise<void>
}

export interface OAuthPlatform {
  /** Open the authorize URL in the system browser; resolves to a closer for that tab. */
  openBrowser(url: string): Promise<() => Promise<void>>
  openLoopback(path: string, timeoutMs: number): Promise<OAuthLoopbackHandle>
}

export interface OAuthLoginDeps {
  platform: OAuthPlatform
}

/** Authorization-server refusals that mean "the user did not complete sign-in", not a real failure. */
const OAUTH_CANCELLATION_CODES = /access_denied|login_required|consent_required|interaction_required|user_cancelled|user_canceled/i

export function isOAuthCancellation(error: unknown): boolean {
  return error instanceof OAuthCancelledError || OAUTH_CANCELLATION_CODES.test(errorMessage(error))
}

export function parseTokenResponse(body: any): TokenSet {
  const accessToken = String(body?.access_token || '')

  if (!accessToken) {
    throw new Error('Gateway token response missing access_token')
  }

  const expiresAt = Number(body?.expires_at)

  return {
    accessToken,
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : 0,
    provider: String(body?.provider || ''),
    refreshToken: String(body?.refresh_token || ''),
    userId: String(body?.user_id || '')
  }
}

/** True when the token is at/near expiry (unknown expiry counts as expired). */
export function tokenNeedsRefresh(tokens: Pick<TokenSet, 'expiresAt'>, nowSeconds: number, skewSeconds = 60): boolean {
  if (!Number.isFinite(tokens.expiresAt) || tokens.expiresAt <= 0) {
    return true
  }

  return nowSeconds >= tokens.expiresAt - skewSeconds
}

export function buildNativeAuthorizeUrl(
  baseUrl: string,
  params: { challenge: string; redirectUri: string; state: string; provider?: string }
): string {
  const query = new URLSearchParams({
    code_challenge: params.challenge,
    code_challenge_method: 'S256',
    redirect_uri: params.redirectUri,
    state: params.state
  })

  if (params.provider) {
    query.set('provider', params.provider)
  }

  return `${baseUrl}/auth/native/authorize?${query.toString()}`
}

/** Read code/state out of the loopback URL the gateway returns; verifies `state` (CSRF). */
export function parseLoopbackCallback(url: string, expectedState: string): { code: string } {
  const parsed = new URL(url, 'http://127.0.0.1')
  const error = parsed.searchParams.get('error')

  if (error) {
    const description = parsed.searchParams.get('error_description') || ''

    throw new Error(`Gateway rejected sign-in: ${error}${description ? ` (${description})` : ''}`)
  }

  const code = parsed.searchParams.get('code') || ''

  if (!code) {
    throw new Error('Sign-in response is missing the authorization code.')
  }

  if (!expectedState || parsed.searchParams.get('state') !== expectedState) {
    throw new Error('Sign-in response state mismatch (possible CSRF); try again.')
  }

  return { code }
}

export interface PasswordLoginInput {
  username: string
  password: string
  /** Provider to use; defaults to the first password provider the gateway advertises. */
  provider?: string
}

/** Runs the full password login and returns the bearer token set. */
export async function passwordLogin(
  transport: HttpTransport,
  probe: ServerProbe,
  input: PasswordLoginInput
): Promise<TokenSet> {
  const { baseUrl } = probe

  if (!probe.authRequired) {
    throw new Error(
      'This Hermes server is not running in gated mode, so a phone cannot sign in. ' +
        'Start it with: hermes serve --host 0.0.0.0 --port 9119'
    )
  }

  const provider = input.provider || probe.providers.find(p => p.supportsPassword)?.name

  if (!provider || !probe.nativeFlow) {
    throw new Error(
      'This Hermes server does not offer username/password sign-in for native apps. ' +
        'Update Hermes on the PC (hermes update) and run "hermes serve --host 0.0.0.0" so it prompts for credentials.'
    )
  }

  const verifier = randomBase64url(32)
  const state = randomBase64url(24)
  const challenge = await s256Challenge(verifier)
  const jar = new CookieJar()

  // 1. Start the native authorization; keep the broker cookie, do not follow /login.
  const authorize = await transport.request({
    followRedirects: false,
    timeoutMs: 15_000,
    url: buildNativeAuthorizeUrl(baseUrl, { challenge, provider, redirectUri: NATIVE_REDIRECT_URI, state })
  })

  jar.store(authorize.setCookie)

  if (authorize.status < 300 || authorize.status >= 400 || jar.size === 0) {
    throw new Error(describeFailure(authorize, 'The gateway did not start a native sign-in'))
  }

  // 2. Submit credentials against the broker handle.
  const login = await transport.request({
    headers: { Cookie: jar.header() },
    json: { next: '', password: input.password, provider, username: input.username },
    method: 'POST',
    timeoutMs: 20_000,
    url: `${baseUrl}/auth/password-login`
  })

  if (login.status === 401) {
    throw new InvalidCredentialsError()
  }

  if (login.status === 429) {
    throw new Error('Too many sign-in attempts. Wait a minute and try again.')
  }

  const loginBody = parseJson(login.body)

  if (login.status >= 400 || !loginBody?.ok || typeof loginBody.next !== 'string') {
    throw new Error(describeFailure(login, 'Sign-in failed'))
  }

  const { code } = parseLoopbackCallback(loginBody.next, state)

  // 3. Redeem the one-time code with the PKCE verifier.
  return redeemNativeCode(transport, baseUrl, code, verifier)
}

/**
 * Step 3 of both login flows: exchange the one-time gateway code + PKCE verifier for a token set.
 * Shared so the password and OAuth flows cannot drift apart on the token contract.
 */
async function redeemNativeCode(transport: HttpTransport, baseUrl: string, code: string, verifier: string): Promise<TokenSet> {
  const token = await transport.request({
    json: { code, code_verifier: verifier },
    method: 'POST',
    timeoutMs: 15_000,
    url: `${baseUrl}/auth/native/token`
  })

  if (token.status >= 400) {
    throw new Error(describeFailure(token, 'Could not exchange the sign-in code'))
  }

  return parseTokenResponse(parseJson(token.body))
}

/**
 * Nous Portal OAuth login (flow B): system browser + a REAL loopback listener + PKCE.
 *
 * Reuses the same PKCE pair, `state` verification, token exchange and downstream refresh as the
 * password flow. Nothing here invents an endpoint: the gateway's `/auth/native/authorize` brokers
 * Portal itself and hands back the same one-time `code`.
 */
export async function nousOAuthLogin(
  transport: HttpTransport,
  probe: ServerProbe,
  deps: OAuthLoginDeps
): Promise<TokenSet> {
  const decision = resolveNousOAuth(probe)

  if (!decision.available) {
    throw new NousProviderUnavailableError(decision.reason)
  }

  const verifier = randomBase64url(32)
  const state = randomBase64url(24)
  const challenge = await s256Challenge(verifier)

  // Bind BEFORE opening the browser: the gateway needs the port, and the socket must be listening
  // by the time the redirect comes back.
  const listener = await deps.platform.openLoopback(OAUTH_LOOPBACK_PATH, OAUTH_CALLBACK_TIMEOUT_MS)
  let closeBrowser: (() => Promise<void>) | null = null

  try {
    assertGatewayLoopbackRedirectUri(listener.redirectUri)

    closeBrowser = await deps.platform.openBrowser(
      buildNativeAuthorizeUrl(probe.baseUrl, {
        challenge,
        provider: NOUS_PROVIDER_NAME,
        redirectUri: listener.redirectUri,
        state
      })
    )

    // The gateway 302s the browser here after Portal redirects back to /auth/callback.
    const callbackUrl = await listener.awaitCallback()

    // Same CSRF check as the password flow: a code that arrives with the wrong `state` is never
    // redeemed.
    const { code } = parseLoopbackCallback(callbackUrl, state)

    return await redeemNativeCode(transport, probe.baseUrl, code, verifier)
  } catch (error) {
    throw isOAuthCancellation(error) ? new OAuthCancelledError() : error
  } finally {
    // Always drop the listener (the port must not outlive the flow) and close our tab.
    await listener.close().catch(() => undefined)

    if (closeBrowser) {
      await closeBrowser().catch(() => undefined)
    }
  }
}

/** Rotate the token pair. Throws NeedsLoginError when the refresh token is rejected. */
export async function refreshTokens(transport: HttpTransport, baseUrl: string, tokens: TokenSet): Promise<TokenSet> {
  if (!tokens.refreshToken) {
    throw new NeedsLoginError()
  }

  const response = await transport.request({
    json: { provider: tokens.provider, refresh_token: tokens.refreshToken },
    method: 'POST',
    timeoutMs: 15_000,
    url: `${baseUrl}/auth/native/refresh`
  })

  if (response.status === 401 || response.status === 403 || response.status === 400) {
    throw new NeedsLoginError()
  }

  if (response.status >= 400) {
    // 503 provider outage etc.: transient, keep the stored tokens.
    throw new HttpStatusError(response.status, response.body)
  }

  const next = parseTokenResponse(parseJson(response.body))

  return { ...next, provider: next.provider || tokens.provider, userId: next.userId || tokens.userId }
}

/**
 * Owns the stored session: hands out a fresh access token, refreshes on demand
 * (single-flight - the gateway rotates refresh tokens with reuse detection, so two
 * concurrent refreshes would revoke the session) and signs out when refresh fails.
 */
export class AuthSession {
  private refreshing: Promise<TokenSet> | null = null

  constructor(
    readonly store: ConnectionStore,
    private readonly transport: HttpTransport,
    private readonly nowSeconds: () => number = () => Date.now() / 1000
  ) {}

  /**
   * Public capability probe so the connect screen can offer the right sign-in options before the
   * user picks one (`/api/status` + `/api/auth/providers`; credential-free).
   */
  async probe(rawUrl: string, policy: TransportPolicyOptions = {}): Promise<ServerProbe> {
    return probeServer(this.transport, rawUrl, policy)
  }

  async requireBaseUrl(): Promise<string> {    const connection = await this.store.getConnection()

    if (!connection) {
      throw new NeedsLoginError('No Hermes server configured. Connect to your PC first.')
    }

    return connection.baseUrl
  }

  /** Probe, log in and persist both the connection descriptor and the tokens. */
  async login(rawUrl: string, input: PasswordLoginInput, policy: TransportPolicyOptions = {}): Promise<ServerProbe> {
    const probe = await probeServer(this.transport, rawUrl, policy)
    const tokens = await passwordLogin(this.transport, probe, input)
    const provider = tokens.provider || input.provider || probe.providers.find(p => p.supportsPassword)?.name || ''

    await this.store.setConnection({
      baseUrl: probe.baseUrl,
      lanCleartextAcceptedFor: policy.allowLanCleartext && isLanCleartext(probe.baseUrl) ? probe.baseUrl : undefined,
      provider,
      username: input.username,
      version: probe.version ?? undefined
    })
    await this.store.setTokens({ ...tokens, provider })

    return probe
  }

  /**
   * Probe, run the Nous Portal OAuth flow and persist the same descriptor + token pair as
   * {@link login}. The rest of the session (refresh, 401 retry, sign-out) is unchanged, so an
   * OAuth session and a password session behave identically once stored.
   */
  async loginWithNous(
    rawUrl: string,
    deps: OAuthLoginDeps,
    policy: TransportPolicyOptions = {}
  ): Promise<ServerProbe> {
    const probe = await probeServer(this.transport, rawUrl, policy)
    const tokens = await nousOAuthLogin(this.transport, probe, deps)
    const provider = tokens.provider || NOUS_PROVIDER_NAME

    await this.store.setConnection({
      baseUrl: probe.baseUrl,
      lanCleartextAcceptedFor: policy.allowLanCleartext && isLanCleartext(probe.baseUrl) ? probe.baseUrl : undefined,
      provider,
      // OAuth has no username to pre-fill; the identity lives in the token's user_id.
      username: '',
      version: probe.version ?? undefined
    })
    await this.store.setTokens({ ...tokens, provider })

    return probe
  }

  async accessToken(): Promise<string> {
    const tokens = await this.store.getTokens()

    if (!tokens?.accessToken) {
      throw new NeedsLoginError()
    }

    if (tokenNeedsRefresh(tokens, this.nowSeconds())) {
      return (await this.refresh(tokens.accessToken)).accessToken
    }

    return tokens.accessToken
  }

  /**
   * Refresh unless another caller already replaced `staleAccessToken`. The in-flight
   * promise is published synchronously (before any await) so concurrent callers
   * always share a single request.
   */
  refresh(staleAccessToken?: string): Promise<TokenSet> {
    if (this.refreshing) {
      return this.refreshing
    }

    const run = (async () => {
      try {
        const current = await this.store.getTokens()

        if (!current) {
          throw new NeedsLoginError()
        }

        if (staleAccessToken && current.accessToken !== staleAccessToken) {
          // Someone else already rotated while we were waiting; use their result.
          return current
        }

        const next = await refreshTokens(this.transport, await this.requireBaseUrl(), current)
        await this.store.setTokens(next)

        return next
      } catch (error) {
        if (error instanceof NeedsLoginError) {
          await this.store.signOut()
        }

        throw error
      } finally {
        this.refreshing = null
      }
    })()

    this.refreshing = run

    return run
  }

  /** Run `request` with a bearer token; on a 401 refresh once and retry. */
  async withBearer<T>(request: (token: string, baseUrl: string) => Promise<T>): Promise<T> {
    const baseUrl = await this.requireBaseUrl()
    const token = await this.accessToken()

    try {
      return await request(token, baseUrl)
    } catch (error) {
      if (!(error instanceof HttpStatusError) || error.statusCode !== 401) {
        throw error
      }

      const refreshed = await this.refresh(token)

      try {
        return await request(refreshed.accessToken, baseUrl)
      } catch (retryError) {
        if (retryError instanceof HttpStatusError && retryError.statusCode === 401) {
          await this.store.signOut()

          throw new NeedsLoginError()
        }

        throw retryError
      }
    }
  }

  /** Bearer sessions have no server-side logout endpoint; dropping the tokens ends the session on this device. */
  async signOut(): Promise<void> {
    await this.store.signOut()
  }
}
