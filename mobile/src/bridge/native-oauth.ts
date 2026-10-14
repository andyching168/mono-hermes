/**
 * Android half of the Nous Portal OAuth login: the native `OAuthLoopback` Capacitor plugin
 * (Java, `android/.../oauth`) plus the system browser (Custom Tabs via `@capacitor/browser`).
 *
 * <h2>Why a real loopback socket, and not a custom scheme</h2>
 * The gateway is the authority on this and it is strict. `_validate_loopback_redirect_uri`
 * (hermes_cli/dashboard_auth/routes.py) rejects everything except `http://` on a canonical
 * loopback IP-literal authority:
 *
 *   - `scheme != "http"`                                  -> 400 (custom scheme impossible)
 *   - `#` present, or userinfo present                     -> 400
 *   - host not exactly `127.0.0.1` / `::1` (`localhost`!)  -> 400 (https App Link impossible)
 *   - non-canonical authority spelling                     -> 400
 *
 * So `com.hermesmovil.app://oauth` and `https://<host>/oauth` cannot be registered as a fix - they
 * are refused before the browser is ever involved. The only supported Android redirect is a real
 * `http://127.0.0.1:<port>/<path>` listener, which is exactly what RFC 8252 §7.3 recommends and
 * what the desktop does with its own `http.Server`.
 *
 * The password flow (`auth.ts` `passwordLogin`) can use a dead loopback URI because the gateway
 * returns that URL inside a JSON body and the app only pattern-matches `code`/`state` out of it.
 * The OAuth flow cannot: the gateway 302s the *browser* to that URI, so something must answer on
 * the port or the code is never delivered.
 *
 * The web fallback exists only so the browser harness/desktop dev build can import this module; it
 * cannot work there (a WebView has no listening socket) and throws a clear error instead.
 */

import { Browser } from '@capacitor/browser'
import { registerPlugin } from '@capacitor/core'

import { OAuthCancelledError, type OAuthLoopbackHandle, type OAuthPlatform } from './auth'

interface OAuthLoopbackNativePlugin {
  start(options: { path: string; timeoutMs?: number }): Promise<{ port: number; path: string; redirectUri: string }>
  awaitCallback(options?: { timeoutMs?: number }): Promise<{ url: string }>
  stop(): Promise<{ stopped: boolean }>
}

/** Raised on a platform with no loopback socket (the browser harness). */
export class OAuthPlatformUnsupportedError extends Error {
  constructor(message = 'Nous Portal sign-in needs the Android app: a browser cannot listen on the loopback callback address.') {
    super(message)
    this.name = 'OAuthPlatformUnsupportedError'
  }
}

const unsupported = (): never => {
  throw new OAuthPlatformUnsupportedError()
}

const webFallback: OAuthLoopbackNativePlugin = {
  awaitCallback: async () => unsupported(),
  start: async () => unsupported(),
  stop: async () => ({ stopped: false })
}

const loopback = registerPlugin<OAuthLoopbackNativePlugin>('OAuthLoopback', { web: webFallback })

function isCancellation(error: unknown): boolean {
  return (error as { code?: unknown } | null)?.code === 'cancelled'
}

export const oauthPlatform: OAuthPlatform = {
  /**
   * Open the authorize URL in the system browser. `@capacitor/browser` uses a Custom Tab on
   * Android, so the Nous password is typed into the real browser (with its own TLS and origin UI)
   * and never into a WebView the app controls.
   *
   * Returns a closer. Must not throw after the tab opened: a missing `close` is not a login failure.
   */
  async openBrowser(url: string): Promise<() => Promise<void>> {
    await Browser.open({ toolbarColor: '#0a0a0a', url })

    return async () => {
      try {
        await Browser.close()
      } catch {
        // The user may have dismissed the tab already, which is a normal cancel path.
      }
    }
  },

  /**
   * Bind the loopback listener and wait for the gateway to redirect the browser to it.
   *
   * Dismissing the Custom Tab fires `browserFinished`; we then stop the native listener, which
   * settles the pending wait immediately as a cancellation instead of leaving the user staring at
   * a spinner until the timeout.
   */
  async openLoopback(path: string, timeoutMs: number): Promise<OAuthLoopbackHandle> {
    const { redirectUri } = await loopback.start({ path, timeoutMs })
    let finished: { remove: () => Promise<void> } | null = null

    try {
      finished = await Browser.addListener('browserFinished', () => {
        void loopback.stop().catch(() => undefined)
      })
    } catch {
      // No listener support: the timeout is then the only cancellation signal.
      finished = null
    }

    const close = async () => {
      await finished?.remove().catch(() => undefined)
      await loopback.stop().catch(() => undefined)
    }

    return {
      close,
      redirectUri,
      async awaitCallback() {
        try {
          return (await loopback.awaitCallback({ timeoutMs })).url
        } catch (error) {
          if (isCancellation(error)) {
            throw new OAuthCancelledError()
          }

          throw error
        }
      }
    }
  }
}
