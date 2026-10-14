package com.hermesmovil.app.oauth;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * Capacitor bridge for {@link OAuthLoopbackServer}: the Android half of the Nous Portal OAuth
 * login.
 *
 * The JS side ({@code src/bridge/native-oauth.ts}) calls {@code start} to learn the ephemeral
 * loopback {@code redirect_uri} it must put in {@code /auth/native/authorize}, opens the system
 * browser (Custom Tab) at the authorize URL, then calls {@code awaitCallback} to receive the
 * {@code ?code=..&state=..} the gateway redirects the browser back with, and finally
 * {@code stop}. Splitting start/await is required because the port has to exist BEFORE the browser
 * is opened.
 *
 * Capacitor runs plugin methods on one shared HandlerThread, so blocking accepts run on a private
 * pool (same pattern as {@link com.hermesmovil.app.net.BoundedHttpPlugin}).
 */
@CapacitorPlugin(name = "OAuthLoopback")
public class OAuthLoopbackPlugin extends Plugin {

    /** Long enough for a real Portal sign-in (the gateway's own pending window is 600 s). */
    private static final long DEFAULT_TIMEOUT_MS = 300_000L;
    private static final long MAX_TIMEOUT_MS = 900_000L;

    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    private OAuthLoopbackServer server;
    private long startedAtMs;

    @Override
    protected void handleOnDestroy() {
        super.handleOnDestroy();
        closeServer();
        executor.shutdownNow();
    }

    private synchronized void closeServer() {
        if (server != null) {
            server.close();
            server = null;
        }
    }

    /** Bind a fresh loopback listener on an ephemeral port. Returns the redirect_uri to use. */
    @PluginMethod
    public void start(PluginCall call) {
        String path = call.getString("path");
        if (path == null) {
            call.reject("path is required", "invalid_request");
            return;
        }
        try {
            OAuthLoopbackServer.validatePath(path);
        } catch (IllegalArgumentException e) {
            call.reject(e.getMessage(), "invalid_request");
            return;
        }
        closeServer();
        try {
            OAuthLoopbackServer created = OAuthLoopbackServer.start(path);
            synchronized (this) {
                server = created;
                startedAtMs = System.currentTimeMillis();
            }
            JSObject out = new JSObject();
            out.put("redirectUri", created.redirectUri());
            out.put("port", created.port());
            out.put("path", created.path());
            call.resolve(out);
        } catch (Exception e) {
            call.reject("Could not open the loopback callback listener: " + e.getMessage(), "loopback_failed");
        }
    }

    /** Wait for the browser to hit the redirect URI. Resolves with the raw request target. */
    @PluginMethod
    public void awaitCallback(PluginCall call) {
        final OAuthLoopbackServer current;
        final long elapsed;
        synchronized (this) {
            current = server;
            elapsed = startedAtMs == 0 ? 0L : System.currentTimeMillis() - startedAtMs;
        }
        if (current == null) {
            call.reject("No loopback listener is running; call start() first.", "not_started");
            return;
        }
        long timeoutMs = clampTimeout(call.getLong("timeoutMs", DEFAULT_TIMEOUT_MS)) - elapsed;
        if (timeoutMs <= 0) {
            call.reject("Timed out waiting for the browser to return to the app.", "timeout");
            return;
        }
        try {
            executor.execute(() -> {
                try {
                    String url = current.awaitCallback(timeoutMs);
                    if (url == null) {
                        // Closed before the browser came back: the user dismissed the Custom Tab
                        // (the JS side calls stop() on browserFinished) or the flow was cancelled.
                        call.reject("Sign-in was cancelled before the browser returned to the app.", "cancelled");
                        return;
                    }
                    JSObject out = new JSObject();
                    out.put("url", url);
                    call.resolve(out);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    call.reject("Sign-in was interrupted.", "cancelled");
                } catch (Exception e) {
                    call.reject(e.getMessage(), "timeout");
                } finally {
                    closeServer();
                }
            });
        } catch (RejectedExecutionException e) {
            call.reject("plugin destroyed", "cancelled");
        }
    }

    /** Drop the listener. Safe to call when nothing is running (cancel / cleanup paths). */
    @PluginMethod
    public void stop(PluginCall call) {
        closeServer();
        JSObject out = new JSObject();
        out.put("stopped", true);
        call.resolve(out);
    }

    private static long clampTimeout(Long requested) {
        if (requested == null || requested <= 0) {
            return DEFAULT_TIMEOUT_MS;
        }
        return Math.min(requested, MAX_TIMEOUT_MS);
    }
}
