package com.hermesmovil.app.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.After;
import org.junit.Test;

/**
 * JVM tests for the RFC 8252 loopback listener behind the Nous Portal OAuth login.
 *
 * These pin the two properties the login depends on: the advertised redirect URI is the canonical
 * shape the gateway's {@code _validate_loopback_redirect_uri} accepts, and only the real callback
 * (right path, right Host, loopback peer) completes the flow.
 */
public class OAuthLoopbackServerTest {

    private static final String PATH = "/hermes-mobile/oauth/callback";
    private OAuthLoopbackServer server;

    @After
    public void tearDown() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    public void advertisesACanonicalLoopbackRedirectUri() throws Exception {
        server = OAuthLoopbackServer.start(PATH);

        String uri = server.redirectUri();

        // http:// + the 127.0.0.1 IP literal + ephemeral port + path: nothing the gateway rejects.
        assertTrue(uri.startsWith("http://127.0.0.1:"));
        assertTrue(uri.endsWith(PATH));
        assertFalse(uri.contains("#"));
        assertFalse(uri.contains("@"));
        assertTrue(server.port() > 0);
        assertEquals("http://127.0.0.1:" + server.port() + PATH, uri);
    }

    @Test
    public void rejectsUnusableCallbackPaths() {
        assertThrows(IllegalArgumentException.class, () -> OAuthLoopbackServer.validatePath(null));
        assertThrows(IllegalArgumentException.class, () -> OAuthLoopbackServer.validatePath(""));
        assertThrows(IllegalArgumentException.class, () -> OAuthLoopbackServer.validatePath("cb"));
        assertThrows(IllegalArgumentException.class, () -> OAuthLoopbackServer.validatePath("/cb?code=x"));
        assertThrows(IllegalArgumentException.class, () -> OAuthLoopbackServer.validatePath("/cb#frag"));
        assertThrows(IllegalArgumentException.class, () -> OAuthLoopbackServer.validatePath("/cb\\x"));
        assertThrows(IllegalArgumentException.class, () -> OAuthLoopbackServer.validatePath("/cb x"));
        assertThrows(IllegalArgumentException.class, () -> OAuthLoopbackServer.validatePath("/caf\u00e9"));
        // A trailing slash is normalised so the advertised URI stays canonical.
        assertEquals("/cb", OAuthLoopbackServer.validatePath("/cb/"));
    }

    @Test
    public void capturesTheCallbackQueryStringAndAnswersTheBrowser() throws Exception {
        server = OAuthLoopbackServer.start(PATH);

        CountDownLatch answered = new CountDownLatch(1);
        AtomicReference<String> responseCode = new AtomicReference<>();

        Thread client = new Thread(() -> {
            try {
                HttpURLConnection connection =
                    (HttpURLConnection) new URL(server.redirectUri() + "?code=GW_CODE&state=STATE_1").openConnection();
                responseCode.set(String.valueOf(connection.getResponseCode()));
                connection.getInputStream().close();
            } catch (IOException e) {
                responseCode.set("io:" + e.getMessage());
            } finally {
                answered.countDown();
            }
        });
        client.start();

        String callback = server.awaitCallback(5000);

        assertEquals(PATH + "?code=GW_CODE&state=STATE_1", callback);
        assertTrue("the listener answered the browser", answered.await(5, TimeUnit.SECONDS));
        assertEquals("200", responseCode.get());
        // Single use: the code is captured and the port is released.
        assertTrue(server.callbackReceived());
    }

    @Test
    public void ignoresOtherPathsAndKeepsWaitingForTheRealCallback() throws Exception {
        server = OAuthLoopbackServer.start(PATH);

        // A favicon / wrong path must NOT consume the flow: the gateway's code is single-use.
        HttpURLConnection favicon =
            (HttpURLConnection) new URL("http://127.0.0.1:" + server.port() + "/favicon.ico").openConnection();
        assertEquals(404, favicon.getResponseCode());
        // HttpURLConnection routes an error response to the error stream, not getInputStream().
        favicon.getErrorStream().close();
        favicon.disconnect();
        assertFalse("a stray request must not complete the flow", server.callbackReceived());

        HttpURLConnection real = (HttpURLConnection) new URL(server.redirectUri() + "?code=REAL&state=S").openConnection();
        assertEquals(200, real.getResponseCode());
        real.getInputStream().close();

        assertEquals(PATH + "?code=REAL&state=S", server.awaitCallback(5000));
    }

    @Test
    public void refusesARequestWhoseHostIsNotTheBoundAuthority() throws Exception {
        server = OAuthLoopbackServer.start(PATH);

        // Simulates a DNS-rebinding page: it can reach 127.0.0.1, but its Host is its own name.
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", server.port()), 2000);
            OutputStream out = socket.getOutputStream();
            out.write(("GET " + PATH + "?code=FORGED&state=S HTTP/1.1\r\nHost: evil.example\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
            assertTrue("403 expected for a foreign Host", reader.readLine().contains("403"));
        }

        assertFalse("a forged callback must not complete the flow", server.callbackReceived());
    }

    @Test
    public void rejectsNonGetMethods() throws Exception {
        server = OAuthLoopbackServer.start(PATH);

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", server.port()), 2000);
            OutputStream out = socket.getOutputStream();
            out.write(("POST " + PATH + " HTTP/1.1\r\nHost: 127.0.0.1:" + server.port() + "\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
            assertTrue(reader.readLine().contains("405"));
        }

        assertFalse(server.callbackReceived());
    }

    @Test
    public void reportsTimeoutInsteadOfHanging() throws Exception {
        server = OAuthLoopbackServer.start(PATH);

        IOException failure = assertThrows(IOException.class, () -> server.awaitCallback(120));
        assertTrue(failure.getMessage().contains("Timed out"));
    }

    @Test
    public void closingWhileWaitingCancelsTheFlow() throws Exception {
        server = OAuthLoopbackServer.start(PATH);

        CountDownLatch waiting = new CountDownLatch(1);
        AtomicReference<String> result = new AtomicReference<>("unset");

        Thread waiter = new Thread(() -> {
            try {
                waiting.countDown();
                result.set(String.valueOf(server.awaitCallback(30_000)));
            } catch (Exception e) {
                result.set("error:" + e.getClass().getSimpleName());
            }
        });
        waiter.setDaemon(true);
        waiter.start();

        assertTrue(waiting.await(5, TimeUnit.SECONDS));
        Thread.sleep(50);
        // The JS side calls stop() when the user dismisses the Custom Tab.
        server.close();
        waiter.join(5000);

        // null == "closed before the callback arrived", which the plugin reports as a cancellation.
        assertEquals("null", result.get());
    }

    @Test
    public void neverBindsAWildcardAddress() throws Exception {
        server = OAuthLoopbackServer.start(PATH);

        // A wildcard bind would leak the pending authorization code to the tailnet/LAN.
        assertTrue(server.redirectUri().contains("127.0.0.1:"));
        assertFalse(server.redirectUri().contains("0.0.0.0"));
    }
}
