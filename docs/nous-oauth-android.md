# Nous Portal OAuth on Android — official API analysis and implementation notes

Scope: adding **Nous Portal OAuth** (`nous` provider) sign-in to the Android client while keeping
**Basic Auth** working. All code changes live under `mobile/`; upstream's renderer is untouched
(`upstream/` is only read, and is pinned).

- Upstream repository: `https://github.com/NousResearch/hermes-agent`
- Pinned commit: `158fd638da1629c8e62caf9ade1515d162def8ab` (Hermes 0.21.5, `mobile/upstream-pin.json`)

## 1. What was inspected

The task referenced `electron/native-oauth.ts` and `native-auth-decisions.ts`. At the pinned commit
they live under `apps/desktop/`, not at the repo root:

| File | Why it matters |
|---|---|
| `apps/desktop/electron/native-oauth.ts` | Pure RFC 8252 helpers: `generatePkcePair`, `generateState`, `statusSupportsNativeFlow`, `resolveLoginStrategy`, `buildNativeAuthorizeUrl`, `parseLoopbackCallback`, `parseTokenResponse`, `tokenNeedsRefresh`, `NATIVE_FLOW_ID = 'native_pkce'`. |
| `apps/desktop/electron/native-auth-decisions.ts` | `normalizeAdvertisedAuthProviders`, `oauthGuardMayHardFail` (all-password providers ⇒ do **not** demand OAuth), `oauthSessionIsLive`, `resolveOauthRestAuth`, `shouldRotateNativeTokenAfterRejection`. |
| `apps/desktop/electron/native-oauth-login.ts` | The Electron-coupled glue (loopback `http.Server`, `shell.openExternal`). |
| `hermes_cli/dashboard_auth/native_flow.py` | The broker store: `register_pending` / `complete_pending` / `redeem_code`, TTLs, caps. |
| `hermes_cli/dashboard_auth/routes.py` | The real endpoint contracts, **including `_validate_loopback_redirect_uri`**. |
| `plugins/dashboard_auth/nous/__init__.py` | The `nous` provider (Portal OAuth client, `client_id` shape `agent:{instance_id}`). |
| `plugins/dashboard_auth/_shared.py` | `validate_redirect_uri` (the **IDP** redirect = the gateway's own `/auth/callback`), `pkce_login_start`. |

Deliberately **not** invented: every endpoint, field name and error code below is read out of the
gateway source, and the mobile code only uses those.

## 2. Why the gateway brokers (and why that shapes Android)

From `native-oauth.ts`'s header: the Portal issues a **per-gateway-instance `client_id`** and only
accepts a `redirect_uri` on the gateway's own origin. A phone therefore cannot be a direct Portal
OAuth client. The gateway is the authorization server *to the client* and an OAuth client *to
Portal*:

```
Android ──(system browser)──> GET /auth/native/authorize?provider=nous&code_challenge=…&redirect_uri=…&state=…
      gateway ──302──> Portal /oauth/authorize (gateway's client_id, gateway's own /auth/callback)
      Portal  ──302──> gateway GET /auth/callback?code=…&state=…      (gateway validates this one)
      gateway ──302──> <client redirect_uri>?code=<gw_code>&state=<client state>
Android ──> POST /auth/native/token {code, code_verifier}   -> bearer tokens
```

There are **two different redirect URIs** and they must not be confused:

| Redirect | Value | Validated by |
|---|---|---|
| Gateway → Portal (IDP redirect) | the gateway's own origin, path must end `/auth/callback` | `validate_redirect_uri` in `_shared.py`; computed by `_redirect_uri(request)` |
| Gateway → client (our redirect) | whatever the app sent to `/auth/native/authorize` | **`_validate_loopback_redirect_uri`** in `routes.py` |

## 3. Endpoint contracts (as implemented by the pinned gateway)

| Endpoint | Request | Success | Failure |
|---|---|---|---|
| `GET /api/status` | — | `{auth_required, auth_flows: ['native_pkce', …], auth_providers: [...], version}` | — |
| `GET /api/auth/providers` | — | `{providers: [{name, display_name, supports_password}]}` | `503 {detail}` when no interactive provider is registered |
| `GET /auth/native/authorize` | `provider`, `code_challenge`, `code_challenge_method=S256`, `redirect_uri`, `state` | OAuth provider: 302 to the IDP (+PKCE cookie carrying `broker`) | `400` for a non-`S256` method, a missing challenge, or a **non-loopback `redirect_uri`**; `404` unknown provider; `400` provider without `supports_session`; `503` broker store full / >8 pending from one IP |
| `POST /auth/native/token` | `{code, code_verifier}` | `{access_token, refresh_token, token_type:'Bearer', expires_at, provider, user_id}` | generic `400` (unknown/expired/replayed code, or PKCE mismatch - the entry is popped *before* the PKCE check, so there is no oracle) |
| `POST /auth/native/refresh` | `{refresh_token, provider}` | same bearer payload, **rotated** refresh token | `401 {error:'session_expired'}` when every provider rejects the RT; `503` when a provider is unreachable but none rotated |

Broker constraints that bound the mobile UX (`native_flow.py`):

- pending authorization TTL **600 s**; issued code TTL **120 s**;
- 256 entries global, **8 pending per client IP**;
- code single-use, PKCE-bound to the *client's* `code_challenge`, compared in constant time.

## 4. The decisive constraint: the redirect URI

`_validate_loopback_redirect_uri` (`hermes_cli/dashboard_auth/routes.py`) is strict and rejects
before the browser is involved:

| Candidate Android redirect | Gateway result |
|---|---|
| `com.hermesmovil.app://oauth` (custom scheme) | 400 — `scheme != "http"` |
| `https://…/auth/callback` (App Link) | 400 — host must be a loopback IP literal |
| `http://localhost:PORT/…` | 400 — `localhost` rejected in favour of IP literals (RFC 8252 §8.3) |
| `http://127.0.0.1:PORT/…`, `http://[::1]:PORT/…` | **accepted** |
| fragment, userinfo, `:08080`, uppercase host, backslash, control chars, non-ASCII | 400 — authority must be canonical |

Consequences:

1. **No URI registration can fix this.** There is no scheme to register in `AndroidManifest.xml`
   for the callback; a custom scheme or App Link is refused by the server, so adding an
   `<intent-filter>` would be dead code and would *look* supported while the login always fails.
2. The existing `NATIVE_REDIRECT_URI = http://127.0.0.1:47321/hermes-mobile/callback` **cannot be
   reused for OAuth**. It is syntactically valid and works for the password flow only because
   `POST /auth/password-login` *returns* it in a JSON body (`{"ok":true,"next":…}`) and the app
   merely parses `code`/`state` out of it — nothing ever fetches it. In the OAuth flow the gateway
   302s the real browser to that URI, so with no listener the browser shows a connection error and
   the code is never delivered.
3. Therefore the supported Android design is a **real loopback listener** (RFC 8252 §7.3), which is
   also what the desktop does with its own `http.Server`.

`isGatewayLoopbackRedirectUri` / `assertGatewayLoopbackRedirectUri` in `mobile/src/bridge/auth.ts`
mirror the gateway's rule, and `nousOAuthLogin` asserts it **before** opening the browser so a
misconfigured listener fails locally with a clear message instead of an opaque gateway 400.
(The gateway preserves a query string, so a query is accepted for parity.)

## 5. Implementation

| File | Change |
|---|---|
| `mobile/android/.../oauth/OAuthLoopbackServer.java` | New. Loopback-only `ServerSocket` on an **ephemeral** port; captures the callback request target. |
| `mobile/android/.../oauth/OAuthLoopbackPlugin.java` | New. Capacitor plugin `OAuthLoopback` (`start` / `awaitCallback` / `stop`). |
| `mobile/android/.../MainActivity.java` | Registers the plugin. |
| `mobile/src/bridge/native-oauth.ts` | New. `oauthPlatform`: Custom Tab via `@capacitor/browser` + the plugin, typed against `OAuthPlatform`. |
| `mobile/src/bridge/auth.ts` | `NOUS_PROVIDER_NAME`, `OAUTH_LOOPBACK_PATH`, `resolveNousOAuth`, `isGatewayLoopbackRedirectUri`, `OAuthPlatform`/`OAuthLoopbackHandle`, `nousOAuthLogin`, `AuthSession.loginWithNous`, `AuthSession.probe`, `redeemNativeCode` (shared), `OAuthCancelledError`, `NousProviderUnavailableError`. |
| `mobile/src/connect-screen.ts` | "Sign in with Nous" button + probe-driven availability hint; both methods share the LAN-consent gate. |
| `docs/how-it-works.md` | Flow documented. |

### Security properties of the Android callback

- Binds `127.0.0.1` only (never a wildcard), ephemeral port ⇒ nothing on the LAN/tailnet, no fixed
  port assumed, two logins cannot collide.
- Accepts only `GET` on the **exact** callback path: a stray request (favicon, wrong path) gets 404
  and the listener keeps waiting rather than burning the single-use gateway code.
- **`Host` must equal the authority we bound.** A DNS-rebinding page can reach `127.0.0.1` but
  cannot make the browser send `Host: 127.0.0.1:<port>`, so the callback cannot be forged from web
  content.
- Bounded request head (8 KB), socket read timeout, single use, and the code is never logged.
- The Portal password is typed into the **system browser** (Custom Tab), never the app's WebView.
- `state` is verified against the value we generated before the code is redeemed (CSRF); a mismatch
  is *not* classified as a cancellation.
- The listener and the tab are always torn down in a `finally`, including on cancel and on error.

### Reuse (no parallel auth stack)

`nousOAuthLogin` reuses `randomBase64url` + `s256Challenge` (PKCE), `parseLoopbackCallback` (state
verification), `redeemNativeCode` (the same `/auth/native/token` exchange the password flow now
calls), `parseTokenResponse`, `refreshTokens`, and `AuthSession` (single-flight refresh, 401 retry
with rotation, sign-out). An OAuth session is stored and behaves identically to a password session.

## 6. Tests

`mobile/test/nous-oauth.test.ts` (18 tests) and
`mobile/android/.../oauth/OAuthLoopbackServerTest.java` (9 tests):

| Required scenario | Where |
|---|---|
| OAuth success | `nousOAuthLogin` … *binds a real loopback listener…* (also asserts `sha256(verifier) == code_challenge` and both cleanups) |
| Cancellation | *treats an access_denied callback as a cancellation…* + the JVM `closingWhileWaitingCancelsTheFlow` |
| State mismatch | *rejects a mismatched state as CSRF (not as a cancel)…* |
| Token expiry | *refreshes an expired token and rotates the stored refresh token* |
| Refresh-token rotation | same test + *shares one rotation between concurrent callers* (the gateway revokes on reuse) |
| Login resume | *persists the connection + tokens … and resumes them without re-authenticating* (no network, no browser) |
| Provider missing | *refuses to start when the gateway has no nous provider (no listener is ever opened)* + `resolveNousOAuth` reasons |
| Basic Auth compatibility | *keeps Basic Auth working unchanged alongside the OAuth path* + *still reports invalid credentials through the password path* |
| Probe detection | *detects the nous provider and native_pkce from /api/status + /api/auth/providers* |
| Redirect parity | *accepts exactly what `_validate_loopback_redirect_uri` accepts* / *refuses every redirect the gateway refuses* |

## 7. Device verification

`mobile/ui-audit/device-oauth.mjs` runs against a real device (or emulator) with the debug APK
installed and **no gateway at all** - it exercises the app's own native side plus a real Custom Tab:

```
cd mobile
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
node ui-audit/device-oauth.mjs
```

Result on a Xiaomi 2407FPN8EG (Android 16 / API 36, arm64-v8a):

| Check | Result |
|---|---|
| native `OAuthLoopback` + `Browser` plugins registered | ok |
| connect screen offers "Sign in with Nous" (visible, 48px, in a 375×834 viewport) | ok |
| `OAuthLoopback.start()` binds an ephemeral loopback port, canonical URI | ok - `http://127.0.0.1:35989/hermes-mobile/oauth/callback` |
| **a real Custom Tab reaches the loopback listener with `code`+`state`** | ok |
| a stray path does not consume the flow | ok |
| `stop()` releases the listener | ok |

This settles the highest-value assumption: a real Android Custom Tab really does navigate to
`http://127.0.0.1:<port>/...` and reach the app's own `ServerSocket` (risk 2 below, now closed). An
earlier manual run captured the Custom Tab rendering the listener's page at `127.0.0.1:44685`, and
the same run drove the app's connect screen with the server URL / username / password fields and both
buttons laid out correctly.

### Real end-to-end against a live Nous Portal

The full flow was completed against a **real, gated `hermes serve` gateway and the real Nous Portal**,
not a mock. The app's stored connection descriptor on the device afterwards reads:

```json
{"baseUrl":"https://hermes.andyching168.synology.me","provider":"nous","username":"","version":"0.21.7"}
```

`provider: "nous"` together with an empty `username` is a fingerprint only `loginWithNous` can write -
the password flow stores `provider: "basic"` plus the typed username - so this session can only have
come from a successful Portal round trip through this implementation. That gateway also reports
`/api/status` → `200 {"version":"0.21.7","gateway_running":true}`, i.e. the run happened against
**0.21.7**, newer than the **0.21.5** pin the contracts in §2-§4 were read from: the flow works
forward of the analysed version, not only on it.

Sealed tokens are present (`hermes.tokens.v1`) and the app resumes the session on relaunch, which
exercises the OAuth `AuthSession` refresh/rotation path against the real gateway too.

## 8. Unverified risks

Everything below is honestly **not** proven by the test suite or by this environment. They are the
things to check before shipping.

1. ~~No real end-to-end run against a live Portal~~ - **verified** (§7): completed against the real
   gateway `https://hermes.andyching168.synology.me` (0.21.7) and the real Nous Portal. The gateway
   contracts in §2-§4 remain *read* from source rather than reconstructed from wire captures, and no
   automated test performs this run - it was a manual, one-off confirmation.
2. ~~Chrome/WebView behaviour on a top-level navigation to `http://127.0.0.1:<port>`~~ - **verified**
   on a real device (§7); the Custom Tab reaches the app's loopback listener. Private Network Access
   policy or a future Chrome change could still break it, so re-run `ui-audit/device-oauth.mjs` when
   bumping Android/Chrome targets.
3. **Custom Tabs availability.** `@capacitor/browser` falls back to `ACTION_VIEW` when no Custom
   Tabs provider exists; that path is untested here, as is the behaviour of `browserFinished`
   (which drives prompt cancellation). If the listener is unaware, cancel degrades to the timeout.
4. **The app process must stay alive** while the browser is in front. Nothing pins it; if Android
   kills the process, the socket dies and the callback is lost (the user retries; the gateway's
   pending entry simply expires after 600 s). The device check above used a foregrounded app, and the
   Portal run did not exercise process death mid-flow.
5. **The `nous` provider only exists when the PC is configured** (`dashboard.oauth.client_id` /
   `HERMES_DASHBOARD_OAUTH_CLIENT_ID`, shape `agent:{instance_id}`). A gateway without it is
   correctly handled (the option is hidden with a reason), but that means the feature cannot be
   exercised at all without a Portal-provisioned instance.
6. **Multiple interactive providers.** With `provider` omitted the gateway renders a provider
   chooser; we always pass `provider=nous`, so the chooser is never shown. If a future gateway
   requires the chooser, the flow would need revisiting.
7. **`expires_at` semantics.** The mobile layer trusts `expires_at` (unix seconds) plus a 60 s skew,
   mirroring upstream. A gateway that returned milliseconds would cause a refresh storm; no
   assertion pins the unit against a live server.
8. **No device test of `stop()` racing a callback.** If `browserFinished` fires in the same instant
   as the final callback, cancellation could win; the JVM test covers the closed-while-waiting case
   but not a genuine race.
9. **Debug APK only.** No release/signing or minified-build verification was performed.
10. **Rotation on a 401 is shared with the password path** (`withBearer`); the OAuth-specific claim
    in `native-auth-decisions.ts` (`shouldRotateNativeTokenAfterRejection`) is mirrored only in the
    sense that a structured 401 triggers one rotation.
