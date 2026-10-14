/**
 * On-device check of the Nous Portal OAuth callback plumbing (emulator or phone).
 *
 *   node ui-audit/device-oauth.mjs
 *
 * Needs only the DEBUG APK installed (WebView remote debugging on, see lib/device.mjs) - NO gateway
 * and no `device-server.mjs`: everything here is the app's own native side plus the system browser.
 *
 * Why this exists as a device test rather than a unit test: the Android login rests on one
 * assumption that no unit test can reach - that a real **Custom Tab** navigating to
 * `http://127.0.0.1:<port>/...` actually lands on the `ServerSocket` the app bound inside its own
 * process, and that the `?code=..&state=..` the gateway appends survives the trip. The gateway's
 * `_validate_loopback_redirect_uri` (hermes_cli/dashboard_auth/routes.py) accepts no other redirect
 * URI, so if this hop fails the whole feature fails - while every mocked test still passes.
 *
 * It asserts through CDP:
 *   a  the native `OAuthLoopback` plugin is registered
 *   b  the connect screen offers "Sign in with Nous" next to Connect, visible, >=44px, in viewport
 *      (only when the app has no stored session; on a phone the stored data is deliberately left
 *      alone, so this check is skipped with a note when the app shell is already up)
 *   c  `OAuthLoopback.start()` binds an ephemeral port on 127.0.0.1 and reports a canonical URI
 *   d  opening that URI in the Custom Tab reaches the listener, and the callback carries code+state
 *   e  the listener rejects a stray path (`/favicon.ico`) instead of consuming the flow
 *   f  `stop()` releases the port
 * Every check prints `ok` / `FAIL <reason>`; a failing check saves ui-audit/device/oauth-<name>.png.
 * Exit code 1 when any check fails. Always closes the CDP socket and removes the adb port forward.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { adb, connect, launchApp, sleep } from './lib/device.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const out = path.join(here, 'device')
fs.mkdirSync(out, { recursive: true })

let total = 0
let failing = 0

function check(name, ok, detail = '') {
  total += 1
  if (ok) {
    console.log(`ok   ${name}${detail ? ` - ${detail}` : ''}`)

    return true
  }
  failing += 1
  console.log(`FAIL ${name}${detail ? ` - ${detail}` : ''}`)
  try {
    fs.writeFileSync(path.join(out, `oauth-${name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}.png`), adb('exec-out', 'screencap', '-p'))
  } catch {}

  return false
}

await launchApp()
const cdp = await connect()

try {
  const registered = await cdp.evaluate(() => Boolean(window.Capacitor?.Plugins?.OAuthLoopback && window.Capacitor?.Plugins?.Browser))

  check('a native OAuthLoopback + Browser plugins registered', registered)

  if (!registered) {
    console.log('\nthe installed APK predates this feature; install the current debug APK and re-run.')
  } else {
    // b - the connect screen, only when it is actually on screen
    const screen = await cdp.evaluate(() => (document.querySelector('.hm-connect form') ? 'connect' : document.querySelector('[data-slot=composer-root]') ? 'app' : 'other'))

    if (screen === 'connect') {
      const dom = await cdp.evaluate(() => {
        const nous = Array.from(document.querySelectorAll('.hm-connect button')).find(b => /nous/i.test(b.textContent || ''))
        const r = nous && nous.getBoundingClientRect()

        return {
          hidden: nous ? nous.hidden : null,
          h: r ? Math.round(r.height) : 0,
          inViewport: Boolean(r) && r.top >= -1 && r.bottom <= window.innerHeight + 1,
          overflow: document.querySelector('.hm-connect .hm-card').scrollWidth > window.innerWidth + 1,
          text: nous ? (nous.textContent || '').trim() : ''
        }
      })

      check('b connect screen offers "Sign in with Nous"', dom.text === 'Sign in with Nous', dom.text || 'missing')
      check('b Nous button is visible and >=44px inside the viewport', !dom.hidden && dom.h >= 44 && dom.inViewport, `${dom.h}px`)
      check('b connect card does not overflow horizontally', !dom.overflow)
    } else {
      console.log(`skip b connect screen not shown (app state: ${screen}); never clearing a phone's stored session`)
    }

    // c - bind an ephemeral loopback listener
    const started = await cdp.evaluate(async () => {
      const s = await window.Capacitor.Plugins.OAuthLoopback.start({ path: '/hermes-mobile/oauth/callback', timeoutMs: 60000 })

      return s
    })

    check('c listener binds an ephemeral port on 127.0.0.1', started.port > 0 && /^http:\/\/127\.0\.0\.1:\d+\/hermes-mobile\/oauth\/callback$/.test(started.redirectUri), started.redirectUri)

    // d+e - a stray path must not consume the flow, then the real Custom Tab must reach the
    // listener. The stray request is fired from the WebView, whose origin (http://localhost) is
    // cross-origin with the listener, so the browser blocks *reading* the 404 - but the request
    // still lands, which is all this needs: what matters is that the real callback still arrives.
    // (The 404 status itself is pinned by OAuthLoopbackServerTest.)
    const result = await cdp.evaluate(async uri => {
      const P = window.Capacitor.Plugins
      const target = `${uri}?code=DEVICE_CODE&state=DEVICE_STATE`

      try {
        await fetch(uri.replace(/\/hermes-mobile\/oauth\/callback$/, '/favicon.ico')).catch(() => undefined)
        const waiting = P.OAuthLoopback.awaitCallback({ timeoutMs: 60000 })
        await P.Browser.open({ url: target })
        const { url } = await waiting

        return { url }
      } catch (error) {
        return { error: `${error.message} (code=${error.code})` }
      } finally {
        await P.Browser.close().catch(() => {})
      }
    }, started.redirectUri)

    check(
      'd Custom Tab reaches the loopback listener with code+state',
      !result.error && /code=DEVICE_CODE/.test(result.url || '') && /state=DEVICE_STATE/.test(result.url || ''),
      result.error || result.url
    )

    check('e a stray path does not consume the flow', !result.error && /code=DEVICE_CODE/.test(result.url || ''), result.error || 'real callback still delivered')

    // f - the port is released
    const stopped = await cdp.evaluate(async () => {
      await window.Capacitor.Plugins.OAuthLoopback.stop()

      try {
        await window.Capacitor.Plugins.OAuthLoopback.awaitCallback({ timeoutMs: 500 })

        return 'still-listening'
      } catch (error) {
        return String(error.code || error.message)
      }
    })

    check('f stop() releases the listener', stopped !== 'still-listening', `awaitCallback -> ${stopped}`)
  }
} finally {
  cdp.close()
  await sleep(500)
}

console.log(`\n${total - failing}/${total} passed`)
process.exit(failing ? 1 : 0)
