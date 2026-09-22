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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;

import org.jboss.logging.Logger;

/**
 * A {@link StartTlsResponse} that drops the TCP connection instead of performing a graceful TLS shutdown, so that
 * {@link #close()} can never block.
 * <p>
 * Closing a TLS socket makes the JDK send {@code close_notify} and then, for anything below TLS 1.3, wait for the peer
 * to answer with its own {@code close_notify}. JNDI layers the TLS socket over the plain LDAP socket with
 * {@code autoClose=false}, which routes that wait through a blocking acquisition of the read lock held by the JNDI
 * reader thread, which in turn sits in a socket read with no timeout. Neither
 * {@code com.sun.jndi.ldap.connect.timeout} nor {@code com.sun.jndi.ldap.read.timeout} covers either of them, so a
 * server that does not answer pins the calling thread forever. As StartTLS also disables connection pooling, every
 * single LDAP operation closes a connection and can get stuck that way, so a handful of such closes is enough to
 * exhaust the worker pool.
 * <p>
 * Closing the underlying socket first unblocks the reader and makes the subsequent TLS shutdown fail fast instead of
 * waiting. The price is that the server sees an abrupt disconnect rather than an orderly TLS shutdown, and may not
 * receive the LDAP unbind JNDI would normally send while tearing the connection down. Already completed operations are
 * unaffected. This is only acceptable because the connection is being disposed of: both callers close the
 * {@link javax.naming.ldap.LdapContext} right after, and unlike the contract of {@link StartTlsResponse#close()} the
 * plaintext connection cannot be used again afterwards.
 */
class StartTlsResponseWithAbruptClose extends StartTlsResponse {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = Logger.getLogger(StartTlsResponseWithAbruptClose.class);

    private final StartTlsResponse delegate;
    private transient SocketCapturingSSLSocketFactory socketFactory;

    StartTlsResponseWithAbruptClose(StartTlsResponse delegate) {
        this.delegate = delegate;
    }

    @Override
    public SSLSession negotiate() throws IOException {
        return negotiate(null);
    }

    @Override
    public SSLSession negotiate(SSLSocketFactory factory) throws IOException {
        socketFactory = new SocketCapturingSSLSocketFactory(factory);
        return delegate.negotiate(socketFactory);
    }

    @Override
    public void close() throws IOException {
        Socket underlyingSocket = socketFactory != null ? socketFactory.underlyingSocket : null;

        try {
            if (underlyingSocket != null) {
                underlyingSocket.close();
            }
        } catch (IOException e) {
            logger.debug("Could not close the socket underlying the StartTLS connection.", e);
        } finally {
            delegate.close();
        }
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        delegate.setEnabledCipherSuites(suites);
    }

    @Override
    public void setHostnameVerifier(HostnameVerifier verifier) {
        delegate.setHostnameVerifier(verifier);
    }

    @Override
    public String getID() {
        return delegate.getID();
    }

    @Override
    public byte[] getEncodedValue() {
        return delegate.getEncodedValue();
    }

    /**
     * Hands out the sockets of the delegate factory while keeping a reference to the plain socket the TLS session was
     * layered over, which is the one that has to be closed to unblock a pending read.
     */
    private static final class SocketCapturingSSLSocketFactory extends SSLSocketFactory {

        private final SSLSocketFactory delegate;
        private volatile Socket underlyingSocket;

        private SocketCapturingSSLSocketFactory(SSLSocketFactory delegate) {
            this.delegate = delegate != null ? delegate : (SSLSocketFactory) SSLSocketFactory.getDefault();
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            // The only variant JNDI uses for StartTLS, and the only one handing us the socket to capture.
            underlyingSocket = s;
            return delegate.createSocket(s, host, port, autoClose);
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return delegate.createSocket(host, port);
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            return delegate.createSocket(host, port, localHost, localPort);
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            return delegate.createSocket(host, port);
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            return delegate.createSocket(address, port, localAddress, localPort);
        }
    }
}