package com.hermesmovil.app.oauth;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Single-use RFC 8252 loopback redirect listener for the Nous Portal OAuth login.
 *
 * <h2>Why this has to be a real socket</h2>
 * The Hermes gateway's {@code _validate_loopback_redirect_uri} (hermes_cli/dashboard_auth/routes.py)
 * accepts a native {@code redirect_uri} ONLY when it is {@code http://} on a literal loopback
 * authority: scheme must be {@code http} (so a custom scheme such as
 * {@code com.hermesmovil.app://oauth} is refused), the host must be the IP literal {@code 127.0.0.1}
 * or {@code ::1} (so {@code localhost} and every {@code https://} App Link are refused), there must
 * be no fragment and no userinfo, and the authority must be spelled canonically.
 *
 * The password flow in {@code auth.ts} gets away with a loopback URI that nothing listens on,
 * because the gateway hands that URL back inside a JSON body ({@code {"next": ...}}) and the app
 * merely parses {@code code}/{@code state} out of it. The OAuth flow is different: the gateway
 * answers the browser with a 302 to that same URI, so a real system browser (Custom Tab) actually
 * navigates to it. Without a listener the browser shows a connection error, the {@code code} is
 * never delivered, and the login cannot complete. This class is that listener.
 *
 * <h2>Security properties</h2>
 * <ul>
 *   <li>Binds {@code 127.0.0.1} only - never a wildcard address, so nothing is exposed to the LAN
 *       or to the tailnet.</li>
 *   <li>Ephemeral port (bind port 0), so no fixed port has to be assumed or registered and two
 *       logins can never collide.</li>
 *   <li>Validates the {@code Host} header against the port we actually bound. A DNS-rebinding page
 *       can point a public name at {@code 127.0.0.1}, but it cannot make the browser send
 *       {@code Host: 127.0.0.1:<port>}, so the callback cannot be forged from a web page.</li>
 *   <li>Only answers the exact expected path; a stray request (favicon, a wrong path) gets 404 and
 *       the server keeps waiting instead of consuming the flow.</li>
 *   <li>Single use: the first accepted callback closes the server.</li>
 *   <li>Bounded: a hard cap on the request line and header block, plus a socket read timeout, so a
 *       local process cannot wedge the login or exhaust memory.</li>
 *   <li>Never logs the authorization code.</li>
 * </ul>
 *
 * Deliberately free of Android imports so it unit-tests as a plain JVM class
 * ({@code src/test/java/.../OAuthLoopbackServerTest.java}).
 */
public final class OAuthLoopbackServer implements Closeable {

    /** The only host the gateway's native-flow validator accepts besides {@code [::1]}. */
    public static final String HOST = "127.0.0.1";

    /** Cap on the whole request head (request line + headers). */
    static final int MAX_REQUEST_BYTES = 8192;
    static final int MAX_HEADERS = 64;
    static final int SOCKET_READ_TIMEOUT_MS = 5000;

    private final ServerSocket socket;
    private final String path;
    private final CountDownLatch done = new CountDownLatch(1);
    private final AtomicReference<String> callback = new AtomicReference<>();
    private final AtomicReference<IOException> failure = new AtomicReference<>();
    private Thread thread;
    private volatile boolean closed;

    private OAuthLoopbackServer(ServerSocket socket, String path) {
        this.socket = socket;
        this.path = path;
    }

    /**
     * Bind a loopback listener on an ephemeral port and start accepting.
     *
     * @param path absolute path the callback must target, e.g. {@code /hermes-mobile/oauth/callback}
     */
    public static OAuthLoopbackServer start(String path) throws IOException {
        String normalised = validatePath(path);
        ServerSocket server = new ServerSocket();
        try {
            // bind port 0 = ephemeral; loopback address only.
            server.bind(new InetSocketAddress(InetAddress.getByName(HOST), 0), 4);
        } catch (IOException e) {
            try { server.close(); } catch (IOException ignored) { /* keep the original failure */ }
            throw e;
        }
        OAuthLoopbackServer loopback = new OAuthLoopbackServer(server, normalised);
        loopback.startAccepting();
        return loopback;
    }

    private void startAccepting() {
        Thread worker = new Thread(this::acceptLoop, "hermes-oauth-loopback");
        worker.setDaemon(true);
        this.thread = worker;
        worker.start();
    }

    /** Path the listener answers on. */
    public String path() {
        return path;
    }

    public int port() {
        return socket.getLocalPort();
    }

    /**
     * The {@code redirect_uri} to hand to {@code /auth/native/authorize}. Canonical by construction:
     * {@code http://127.0.0.1:<port><path>} (no fragment, no userinfo, ASCII).
     */
    public String redirectUri() {
        return "http://" + HOST + ":" + port() + path;
    }

    /**
     * Block until the browser arrives at the redirect URI, or the timeout lapses.
     *
     * @return the request target the browser asked for, e.g.
     *         {@code /hermes-mobile/oauth/callback?code=...&state=...}, or {@code null} when the
     *         listener was closed before any callback arrived (the user dismissed the browser, or
     *         the flow was cancelled).
     * @throws IOException on timeout or if the accept loop failed
     */
    public String awaitCallback(long timeoutMs) throws IOException, InterruptedException {
        if (!done.await(Math.max(1L, timeoutMs), TimeUnit.MILLISECONDS)) {
            throw new IOException("Timed out waiting for the browser to return to the app.");
        }
        IOException error = failure.get();
        if (error != null) {
            throw error;
        }
        return callback.get();
    }

    /** True once the exact callback path has been captured. */
    public boolean callbackReceived() {
        return callback.get() != null;
    }

    @Override
    public void close() {
        closed = true;
        try {
            socket.close();
        } catch (IOException ignored) {
            // Closing an already-closed / never-connected listener is not an error.
        }
        // Unblock awaitCallback() so a cancel (user backs out of the browser) cannot hang the login.
        done.countDown();
    }

    // ---- internals ---------------------------------------------------------

    private void acceptLoop() {
        while (!closed) {
            try (Socket client = socket.accept()) {
                handle(client);
            } catch (IOException e) {
                if (!closed) {
                    failure.compareAndSet(null, e);
                    done.countDown();
                }
                return;
            } catch (Throwable t) {
                // A browser that aborts mid-request must not kill the listener.
                if (closed) {
                    return;
                }
            }
        }
    }

    private void handle(Socket client) {
        try {
            client.setSoTimeout(SOCKET_READ_TIMEOUT_MS);

            if (!isLoopback(client.getInetAddress())) {
                write(client, 403, "Only loopback connections are accepted.");
                return;
            }

            String head = readHead(client.getInputStream());
            if (head == null) {
                write(client, 400, "Malformed request.");
                return;
            }

            String[] lines = head.split("\r?\n");
            String requestLine = lines[0];
            String[] parts = requestLine.split(" ");

            if (parts.length < 2 || !"GET".equals(parts[0])) {
                write(client, 405, "Only GET is supported.");
                return;
            }

            String target = parts[1];
            int query = target.indexOf('?');
            String targetPath = query < 0 ? target : target.substring(0, query);

            // Only the exact callback path completes the flow: a favicon or a wrong path must not
            // consume the authorization (which is single-use on the gateway side too).
            if (!path.equals(targetPath)) {
                write(client, 404, "Not found.");
                return;
            }

            // The Host header is the anti-DNS-rebinding check: only the authority WE bound is
            // accepted, so a web page cannot reach this listener through a rebinding hostname.
            if (!hostAllowed(lines)) {
                write(client, 403, "Unexpected Host header.");
                return;
            }

            if (target.indexOf('#') >= 0 || !target.startsWith("/")) {
                write(client, 400, "Malformed request target.");
                return;
            }

            if (!compareAndSetCallback(target)) {
                write(client, 409, "Sign-in already completed.");
                return;
            }

            write(client, 200, "<!doctype html><meta charset=utf-8><title>Signed in</title>"
                + "<p>Signed in to Mono Hermes. You can close this tab and return to the app.</p>");
        } catch (Throwable t) {
            // Never let one bad request escape: the flow may still complete on a later connection.
        }
    }

    private boolean compareAndSetCallback(String target) {
        if (!callback.compareAndSet(null, target)) {
            return false;
        }
        closed = true;
        try {
            socket.close();
        } catch (IOException ignored) {
            // The callback is already captured; the listener is done either way.
        }
        done.countDown();
        return true;
    }

    private static boolean isLoopback(InetAddress address) {
        return address != null && address.isLoopbackAddress();
    }

    /** Accept {@code 127.0.0.1} / {@code 127.0.0.1:<port>} only (case-insensitive, port optional). */
    private boolean hostAllowed(String[] lines) {
        String host = null;
        for (int i = 1; i < lines.length && i <= MAX_HEADERS; i++) {
            String line = lines[i];
            if (line.isEmpty()) {
                break;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            if ("host".equalsIgnoreCase(line.substring(0, colon).trim())) {
                host = line.substring(colon + 1).trim().toLowerCase(Locale.ROOT);
                break;
            }
        }
        if (host == null) {
            // HTTP/1.0 may omit Host; the socket is already loopback-bound, so accept it.
            return true;
        }
        return host.equals(HOST) || host.equals(HOST + ":" + port());
    }

    /** Read up to the end of the header block, bounded by {@link #MAX_REQUEST_BYTES}. */
    private static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(512);
        int b;
        while ((b = in.read()) != -1) {
            if (buf.size() >= MAX_REQUEST_BYTES) {
                throw new IOException("Request head is too large.");
            }
            buf.write(b);
            byte[] seen = buf.toByteArray();
            int n = seen.length;
            if (n >= 4 && seen[n - 4] == '\r' && seen[n - 3] == '\n' && seen[n - 2] == '\r' && seen[n - 1] == '\n') {
                break;
            }
            if (n >= 2 && seen[n - 2] == '\n' && seen[n - 1] == '\n') {
                break;
            }
        }
        return buf.size() == 0 ? null : buf.toString(StandardCharsets.ISO_8859_1);
    }

    private static void write(Socket client, int status, String html) {
        byte[] body = html.getBytes(StandardCharsets.UTF_8);
        String reason = status == 200 ? "OK" : status == 404 ? "Not Found" : status == 405 ? "Method Not Allowed" : "Error";
        String head = "HTTP/1.1 " + status + " " + reason + "\r\n"
            + "Content-Type: text/html; charset=utf-8\r\n"
            + "Content-Length: " + body.length + "\r\n"
            + "Cache-Control: no-store\r\n"
            + "Connection: close\r\n\r\n";
        try {
            OutputStream out = client.getOutputStream();
            out.write(head.getBytes(StandardCharsets.ISO_8859_1));
            out.write(body);
            out.flush();
        } catch (IOException ignored) {
            // The browser may close early; nothing to do.
        }
    }

    /**
     * Normalise + validate the callback path. Absolute, ASCII, no query/fragment, so the URI this
     * server advertises always satisfies the gateway's canonical-loopback rule.
     */
    static String validatePath(String path) {
        if (path == null || path.isEmpty() || !path.startsWith("/")) {
            throw new IllegalArgumentException("callback path must be absolute (start with '/')");
        }
        if (path.indexOf('?') >= 0 || path.indexOf('#') >= 0) {
            throw new IllegalArgumentException("callback path must not contain a query or fragment");
        }
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c > 0x7F || c <= 0x20 || c == 0x7F || c == '\\') {
                throw new IllegalArgumentException("callback path must be plain ASCII with no controls or backslashes");
            }
        }
        return path.length() > 1 && path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }
}
