/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.storage.ldap.idm.store.ldap;

import java.io.Closeable;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Assert;
import org.junit.Test;

/**
 * Reproduces the shutdown that used to hang: a TLS 1.2 session layered over an existing socket the way JNDI does it,
 * a reader already blocked inside the TLS input stream, and a peer that never answers the {@code close_notify}.
 */
public class StartTlsResponseWithAbruptCloseTest {

    private static final String KEYSTORE = "starttls-server.p12";
    private static final char[] KEYSTORE_PASSWORD = "password".toCharArray();

    /**
     * From TLS 1.3 on the shutdown is half-close and never waits for the peer, so the hang only shows below it.
     */
    private static final String[] TLS_1_2 = new String[] { "TLSv1.2" };

    private static final long TIMEOUT_MILLIS = TimeUnit.SECONDS.toMillis(5);

    @Test(timeout = 30000)
    public void closeReturnsWhileAReaderIsBlockedAndThePeerWithholdsCloseNotify() throws Exception {
        KeyStore keyStore = loadKeyStore();
        SSLSocketFactory serverFactory = serverContext(keyStore).getSocketFactory();
        SSLSocketFactory clientFactory = clientContext(keyStore).getSocketFactory();

        CountDownLatch testDone = new CountDownLatch(1);
        AtomicReference<Throwable> peerFailure = new AtomicReference<>();
        AtomicReference<Throwable> closeFailure = new AtomicReference<>();
        SignallingSocket underlying = null;
        Thread peerThread = null;
        Thread reader = null;
        Thread closer = null;

        try (ServerSocket peer = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            peerThread = silentPeer(peer, serverFactory, testDone, peerFailure);
            peerThread.start();

            underlying = new SignallingSocket(InetAddress.getLoopbackAddress(), peer.getLocalPort());
            LayeringStartTlsResponse delegate = new LayeringStartTlsResponse(underlying);
            StartTlsResponseWithAbruptClose response = new StartTlsResponseWithAbruptClose(delegate);
            response.negotiate(clientFactory);

            Assert.assertEquals("TLSv1.2", delegate.layered.getSession().getProtocol());

            underlying.armed = true;
            reader = blockedReader(delegate.layered);
            reader.start();

            // Reaching the raw socket read means the reader is past the read lock the shutdown has to acquire.
            Assert.assertTrue("the reader never reached the blocking read",
                    underlying.readEntered.await(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));

            // Closing on its own thread, as a hung close cannot be interrupted out of the lock it waits on.
            CountDownLatch closeReturned = new CountDownLatch(1);
            closer = closer(response, closeFailure, closeReturned);
            closer.start();

            Assert.assertTrue("close() did not return, the TLS shutdown is waiting for the peer again",
                    closeReturned.await(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
            Assert.assertNull(closeFailure.get());
            Assert.assertTrue("the socket underneath the TLS session was left open", underlying.isClosed());
            Assert.assertTrue("the TLS shutdown was not delegated", delegate.closed);

            reader.join(TIMEOUT_MILLIS);
            Assert.assertFalse("the blocked reader was never released", reader.isAlive());
        } finally {
            // Releases both the reader and a close that is still stuck, so the threads below can be joined.
            closeQuietly(underlying);
            testDone.countDown();
            join(closer);
            join(reader);
            join(peerThread);
        }

        Assert.assertNull(peerFailure.get());
    }

    /**
     * Accepts one TLS 1.2 connection and then goes quiet, so it neither answers nor triggers a {@code close_notify}.
     */
    private static Thread silentPeer(ServerSocket peer, SSLSocketFactory factory, CountDownLatch testDone,
            AtomicReference<Throwable> failure) {
        Thread thread = new Thread(() -> {
            Socket accepted = null;
            SSLSocket tls = null;

            try {
                accepted = peer.accept();
                tls = (SSLSocket) factory.createSocket(accepted, accepted.getInetAddress().getHostAddress(),
                        accepted.getPort(), false);
                tls.setUseClientMode(false);
                tls.setEnabledProtocols(TLS_1_2);
                tls.startHandshake();
                testDone.await();
            } catch (Exception e) {
                failure.compareAndSet(null, e);
            } finally {
                // The raw socket first, otherwise closing the TLS wrapper waits for a close_notify of its own.
                closeQuietly(accepted);
                closeQuietly(tls);
            }
        }, "starttls-silent-peer");
        thread.setDaemon(true);
        return thread;
    }

    /**
     * Blocks inside the TLS input stream, which is what holds the read lock the shutdown used to wait for.
     */
    private static Thread blockedReader(SSLSocket layered) {
        Thread thread = new Thread(() -> {
            try {
                layered.getInputStream().read();
            } catch (IOException expected) {
                // the connection is dropped underneath the reader, which is the point
            }
        }, "starttls-blocked-reader");
        thread.setDaemon(true);
        return thread;
    }

    private static Thread closer(StartTlsResponse response, AtomicReference<Throwable> failure,
            CountDownLatch returned) {
        Thread thread = new Thread(() -> {
            try {
                response.close();
            } catch (Throwable t) {
                failure.compareAndSet(null, t);
            } finally {
                returned.countDown();
            }
        }, "starttls-closer");
        thread.setDaemon(true);
        return thread;
    }

    private static void join(Thread thread) throws InterruptedException {
        if (thread != null) {
            thread.join(TIMEOUT_MILLIS);
        }
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static KeyStore loadKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = StartTlsResponseWithAbruptCloseTest.class.getResourceAsStream(KEYSTORE)) {
            keyStore.load(in, KEYSTORE_PASSWORD);
        }
        return keyStore;
    }

    private static SSLContext serverContext(KeyStore keyStore) throws Exception {
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, KEYSTORE_PASSWORD);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), null, null);
        return context;
    }

    private static SSLContext clientContext(KeyStore keyStore) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("starttls", keyStore.getCertificateChain("starttls")[0]);

        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustManagers.getTrustManagers(), null);
        return context;
    }

    /**
     * Reports when something starts reading from the socket the TLS session is layered over. A layered
     * {@code SSLSocket} takes that stream once and only reaches it from inside its own read, past the read lock, so
     * this pins down the moment the reader holds that lock instead of waiting for it to be likely.
     */
    private static final class SignallingSocket extends Socket {

        private final CountDownLatch readEntered = new CountDownLatch(1);

        /** Set once the handshake, which reads from the same stream, is over. */
        private volatile boolean armed;

        private SignallingSocket(InetAddress address, int port) throws IOException {
            super(address, port);
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return new FilterInputStream(super.getInputStream()) {
                @Override
                public int read() throws IOException {
                    signal();
                    return super.read();
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    signal();
                    return super.read(b, off, len);
                }

                private void signal() {
                    if (armed) {
                        readEntered.countDown();
                    }
                }
            };
        }
    }

    /**
     * Layers the TLS session over an existing socket exactly the way {@code com.sun.jndi.ldap.ext.StartTlsResponseImpl}
     * does, including the {@code autoClose=false} that makes the JDK wait for the peer on shutdown.
     */
    private static final class LayeringStartTlsResponse extends StartTlsResponse {

        private final Socket underlying;
        private SSLSocket layered;
        private volatile boolean closed;

        private LayeringStartTlsResponse(Socket underlying) {
            this.underlying = underlying;
        }

        @Override
        public SSLSession negotiate() throws IOException {
            return negotiate((SSLSocketFactory) SSLSocketFactory.getDefault());
        }

        @Override
        public SSLSession negotiate(SSLSocketFactory factory) throws IOException {
            layered = (SSLSocket) factory.createSocket(underlying, "localhost", underlying.getPort(), false);
            layered.setEnabledProtocols(TLS_1_2);
            layered.startHandshake();
            return layered.getSession();
        }

        @Override
        public void close() throws IOException {
            closed = true;
            layered.close();
        }

        @Override
        public void setEnabledCipherSuites(String[] suites) {
        }

        @Override
        public void setHostnameVerifier(HostnameVerifier verifier) {
        }
    }
}
