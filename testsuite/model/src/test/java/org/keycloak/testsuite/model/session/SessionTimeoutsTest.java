/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.testsuite.model.session;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.keycloak.common.util.Time;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.testsuite.model.KeycloakModelTest;
import org.keycloak.testsuite.model.RequireProvider;
import org.keycloak.testsuite.model.infinispan.InfinispanTestUtil;

/**
 * <p>
 * Test that checks the Infinispan user session provider expires the sessions
 * correctly and does not remain client sessions in memory after user session
 * expiration.</p>
 *
 * @author rmartinc
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RequireProvider(UserSessionProvider.class)
@RequireProvider(UserProvider.class)
@RequireProvider(RealmProvider.class)
public class SessionTimeoutsTest extends KeycloakModelTest {

    private String realmId;

    @Override
    public void createEnvironment(KeycloakSession s) {
        RealmModel realm = createRealm(s, "test");
        realm.setDefaultRole(s.roles().addRealmRole(realm, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realm.getName()));
        this.realmId = realm.getId();

        s.users().addUser(realm, "user1").setEmail("user1@localhost");

        createClients(s, realm);
        InfinispanTestUtil.setTestingTimeService(s);
    }

    @Override
    public void cleanEnvironment(KeycloakSession s) {
        InfinispanTestUtil.revertTimeService(s);
        RealmModel realm = s.realms().getRealm(realmId);
        s.sessions().removeUserSessions(realm);

        s.realms().removeRealm(realmId);
    }

    protected static void createClients(KeycloakSession s, RealmModel realm) {
        ClientModel clientModel = s.clients().addClient(realm, "test-app");
        clientModel.setEnabled(true);
        clientModel.setBaseUrl("http://localhost:8180/auth/realms/master/app/auth");
        Set<String> redirects = new HashSet<>(Arrays.asList("http://localhost:8180/auth/realms/master/app/auth/*",
                "https://localhost:8543/auth/realms/master/app/auth/*",
                "http://localhost:8180/auth/realms/test/app/auth/*",
                "https://localhost:8543/auth/realms/test/app/auth/*"));
        clientModel.setRedirectUris(redirects);
        clientModel.setSecret("password");

        clientModel = s.clients().addClient(realm, "third-party");
        clientModel.setEnabled(true);
        clientModel.setConsentRequired(true);
        clientModel.setBaseUrl("http://localhost:8180/auth/realms/master/app/auth");
        clientModel.setRedirectUris(redirects);
        clientModel.setSecret("password");
    }

    protected static RealmModel createRealm(KeycloakSession s, String name) {
        RealmModel realm = s.realms().getRealmByName(name);
        if (realm != null) {
            // The previous test didn't clean up the realm for some reason, cleanup now
            s.realms().removeRealm(realm.getId());
        }
        realm = s.realms().createRealm(name);
        return realm;
    }

    protected static UserSessionModel createUserSession(KeycloakSession session, RealmModel realm, UserModel user, boolean offline) {
        UserSessionModel userSession = session.sessions().createUserSession(UUID.randomUUID().toString(), realm, user, "user1", "127.0.0.1",
                "form", true, null, null, UserSessionModel.SessionPersistenceState.PERSISTENT);
        if (offline) {
            userSession = session.sessions().createOfflineUserSession(userSession);
        }
        return userSession;
    }

    protected static AuthenticatedClientSessionModel createClientSession(KeycloakSession session, String realmId, ClientModel client,
            UserSessionModel userSession, String redirect, String state) {
        RealmModel realm = session.realms().getRealm(realmId);
        AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client, userSession);
        if (userSession.isOffline()) {
            clientSession = session.sessions().createOfflineClientSession(clientSession, userSession);
        }
        clientSession.setRedirectUri(redirect);
        if (state != null) {
            clientSession.setNote(OIDCLoginProtocol.STATE_PARAM, state);
        }
        return clientSession;
    }

    protected static UserSessionModel getUserSession(KeycloakSession session, RealmModel realm, String id, boolean offline) {
        return offline
                ? session.sessions().getOfflineUserSession(realm, id)
                : session.sessions().getUserSession(realm, id);
    }

    protected static String cacheName(boolean user, boolean offline) {
        if (user) {
            return offline ? InfinispanConnectionProvider.OFFLINE_USER_SESSION_CACHE_NAME : InfinispanConnectionProvider.USER_SESSION_CACHE_NAME;
        } else {
            return offline ? InfinispanConnectionProvider.OFFLINE_CLIENT_SESSION_CACHE_NAME : InfinispanConnectionProvider.CLIENT_SESSION_CACHE_NAME;
        }
    }

    protected void testUserClientMaxLifespanSmallerThanSession(boolean offline, boolean overrideInClient) {
        withRealm(realmId, (session, realm) -> {
            realm.setOfflineSessionMaxLifespanEnabled(true);
            realm.setOfflineSessionMaxLifespan(3000);
            realm.setOfflineSessionIdleTimeout(7200);
            realm.setClientOfflineSessionIdleTimeout(7200);
            realm.setSsoSessionMaxLifespan(3000);
            realm.setSsoSessionIdleTimeout(7200);
            realm.setClientSessionIdleTimeout(7200);

            // set client session max lifespan smaller at realm or client
            ClientModel client = realm.getClientByClientId("test-app");
            if (overrideInClient) {
                realm.setClientOfflineSessionMaxLifespan(3000);
                realm.setClientSessionMaxLifespan(3000);
                client.setAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_MAX_LIFESPAN, "2000");
                client.setAttribute(OIDCConfigAttributes.CLIENT_SESSION_MAX_LIFESPAN, "2000");
            } else {
                realm.setClientOfflineSessionMaxLifespan(2000);
                realm.setClientSessionMaxLifespan(2000);
                client.removeAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_MAX_LIFESPAN);
                client.removeAttribute(OIDCConfigAttributes.CLIENT_SESSION_MAX_LIFESPAN);
            }
            return null;
        });

        try {
            final String[] sessions = inComittedTransaction(session -> {
                RealmModel realm = session.realms().getRealm(realmId);

                UserModel user = session.users().getUserByUsername(realm, "user1");
                UserSessionModel userSession = createUserSession(session, realm, user, offline);
                Assert.assertEquals(offline, userSession.isOffline());
                AuthenticatedClientSessionModel clientSession = createClientSession(session, realmId, realm.getClientByClientId("test-app"), userSession, "http://redirect", "state");
                return new String[]{userSession.getId(), clientSession.getId()};
            });

            setTimeOffset(1000);

            inComittedTransaction(session -> {
                // refresh sessions at half-time => both session should exist
                RealmModel realm = session.realms().getRealm(realmId);
                ClientModel client = realm.getClientByClientId("test-app");
                UserSessionModel userSession = getUserSession(session, realm, sessions[0], offline);
                Assert.assertNotNull(userSession);
                Assert.assertNotNull(userSession.getAuthenticatedClientSessionByClient(client.getId()));
            });

            setTimeOffset(2100);

            sessions[1] = inComittedTransaction(session -> {
                // refresh sessions after 2000 => only user session should exist
                RealmModel realm = session.realms().getRealm(realmId);
                session.getContext().setRealm(realm);
                ClientModel client = realm.getClientByClientId("test-app");
                UserSessionModel userSession = getUserSession(session, realm, sessions[0], offline);
                Assert.assertNotNull(userSession);
                Assert.assertNull(userSession.getAuthenticatedClientSessionByClient(client.getId()));
                // recreate client session
                AuthenticatedClientSessionModel clientSession = createClientSession(session, realmId, realm.getClientByClientId("test-app"), userSession, "http://redirect", "state");
                return clientSession.getId();
            });

            setTimeOffset(2500);

            inComittedTransaction(session -> {
                // refresh sessions before expiration
                RealmModel realm = session.realms().getRealm(realmId);
                ClientModel client = realm.getClientByClientId("test-app");
                UserSessionModel userSession = getUserSession(session, realm, sessions[0], offline);
                Assert.assertNotNull(userSession);
                Assert.assertNotNull(userSession.getAuthenticatedClientSessionByClient(client.getId()));
            });

            setTimeOffset(3100);

            inComittedTransaction(session -> {
                // ensure user session is expired after user session expiration
                RealmModel realm = session.realms().getRealm(realmId);
                InfinispanConnectionProvider prov = session.getProvider(InfinispanConnectionProvider.class);
                Assert.assertNull(getUserSession(session, realm, sessions[0], offline));
            });
        } finally {
            setTimeOffset(0);
        }
    }

    protected void testUserClientMaxLifespanGreaterThanSession(boolean offline, boolean overrideInClient) {
        withRealm(realmId, (session, realm) -> {
            realm.setOfflineSessionMaxLifespanEnabled(true);
            realm.setOfflineSessionMaxLifespan(3000);
            realm.setOfflineSessionIdleTimeout(7200);
            realm.setClientOfflineSessionIdleTimeout(7200);
            realm.setSsoSessionMaxLifespan(3000);
            realm.setSsoSessionIdleTimeout(7200);
            realm.setClientSessionIdleTimeout(7200);

            // set client session max lifespan bigger at realm or client
            ClientModel client = realm.getClientByClientId("test-app");
            if (overrideInClient) {
                realm.setClientOfflineSessionMaxLifespan(3000);
                realm.setClientSessionMaxLifespan(3000);
                client.setAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_MAX_LIFESPAN, "5000");
                client.setAttribute(OIDCConfigAttributes.CLIENT_SESSION_MAX_LIFESPAN, "5000");
            } else {
                realm.setClientOfflineSessionMaxLifespan(5000);
                realm.setClientSessionMaxLifespan(5000);
                client.removeAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_MAX_LIFESPAN);
                client.removeAttribute(OIDCConfigAttributes.CLIENT_SESSION_MAX_LIFESPAN);
            }
            return null;
        });

        try {
            final String[] sessions = inComittedTransaction(session -> {
                RealmModel realm = session.realms().getRealm(realmId);

                UserModel user = session.users().getUserByUsername(realm, "user1");
                UserSessionModel userSession = createUserSession(session, realm, user, offline);
                Assert.assertEquals(offline, userSession.isOffline());
                AuthenticatedClientSessionModel clientSession = createClientSession(session, realmId, realm.getClientByClientId("test-app"), userSession, "http://redirect", "state");
                return new String[]{userSession.getId(), clientSession.getId()};
            });

            setTimeOffset(2000);

            inComittedTransaction(session -> {
                // refresh sessions before user session expires => both session should exist
                RealmModel realm = session.realms().getRealm(realmId);
                ClientModel client = realm.getClientByClientId("test-app");
                UserSessionModel userSession = getUserSession(session, realm, sessions[0], offline);
                Assert.assertNotNull(userSession);
                Assert.assertNotNull(userSession.getAuthenticatedClientSessionByClient(client.getId()));
            });

            setTimeOffset(3100);

            inComittedTransaction(session -> {
                // ensure user session is expired after user session expiration
                RealmModel realm = session.realms().getRealm(realmId);
                Assert.assertNull(getUserSession(session, realm, sessions[0], offline));
            });
        } finally {
            setTimeOffset(0);
        }
    }

    protected void testUserClientIdleTimeoutSmallerThanSession(int refreashTimes, boolean offline, boolean overrideInClient) {
        withRealm(realmId, (session, realm) -> {
            realm.setOfflineSessionMaxLifespanEnabled(true);
            realm.setOfflineSessionMaxLifespan(7200);
            realm.setClientOfflineSessionMaxLifespan(7200);
            realm.setOfflineSessionIdleTimeout(3000);
            realm.setSsoSessionMaxLifespan(7200);
            realm.setClientSessionMaxLifespan(7200);
            realm.setSsoSessionIdleTimeout(3000);

            // set client session idle smaller at realm or client
            ClientModel client = realm.getClientByClientId("test-app");
            if (overrideInClient) {
                realm.setClientOfflineSessionIdleTimeout(3000);
                realm.setClientSessionIdleTimeout(3000);
                client.setAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_IDLE_TIMEOUT, "2000");
                client.setAttribute(OIDCConfigAttributes.CLIENT_SESSION_IDLE_TIMEOUT, "2000");
            } else {
                realm.setClientOfflineSessionIdleTimeout(2000);
                realm.setClientSessionIdleTimeout(2000);
                client.removeAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_IDLE_TIMEOUT);
                client.removeAttribute(OIDCConfigAttributes.CLIENT_SESSION_IDLE_TIMEOUT);
            }
            return null;
        });

        try {
            final String[] sessions = inComittedTransaction(session -> {
                RealmModel realm = session.realms().getRealm(realmId);

                UserModel user = session.users().getUserByUsername(realm, "user1");
                UserSessionModel userSession = createUserSession(session, realm, user, offline);
                Assert.assertEquals(offline, userSession.isOffline());
                AuthenticatedClientSessionModel clientSession = createClientSession(session, realmId, realm.getClientByClientId("test-app"), userSession, "http://redirect", "state");
                return new String[]{userSession.getId(), clientSession.getId()};
            });

            int offset = 0;
            for (int i = 0; i < refreashTimes; i++) {
                offset += 1500;
                setTimeOffset(offset);
                inComittedTransaction(session -> {
                    // refresh sessions before user session expires => both session should exist
                    RealmModel realm = session.realms().getRealm(realmId);
                    ClientModel client = realm.getClientByClientId("test-app");
                    UserSessionModel userSession = getUserSession(session, realm, sessions[0], offline);
                    Assert.assertNotNull(userSession);
                    AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
                    Assert.assertNotNull(clientSession);
                    userSession.setLastSessionRefresh(Time.currentTime());
                    clientSession.setTimestamp(Time.currentTime());
                });
            }

            offset += 2100;
            setTimeOffset(offset);
            sessions[1] = inComittedTransaction(session -> {
                // refresh sessions after 2000 => only user session should exist, client should be expired by idle
                RealmModel realm = session.realms().getRealm(realmId);
                session.getContext().setRealm(realm);
                ClientModel client = realm.getClientByClientId("test-app");
                UserSessionModel userSession = getUserSession(session, realm, sessions[0], offline);
                Assert.assertNotNull(userSession);
                Assert.assertNull(userSession.getAuthenticatedClientSessionByClient(client.getId()));
                // recreate client session
                AuthenticatedClientSessionModel clientSession = createClientSession(session, realmId, realm.getClientByClientId("test-app"), userSession, "http://redirect", "state");
                return clientSession.getId();
            });

            offset += 3100;
            setTimeOffset(offset);
            inComittedTransaction(session -> {
                // ensure user session is expired after user session expiration
                RealmModel realm = session.realms().getRealm(realmId);
                Assert.assertNull(getUserSession(session, realm, sessions[0], offline));
            });
        } finally {
            setTimeOffset(0);
        }
    }

    @Test
    public void testOfflineUserClientMaxLifespanGreaterThanSession() {
        testUserClientMaxLifespanGreaterThanSession(true, false);
    }

    @Test
    public void testOfflineUserClientMaxLifespanGreaterThanSessionOverrideInClient() {
        testUserClientMaxLifespanGreaterThanSession(true, true);
    }

    @Test
    public void testOfflineUserClientMaxLifespanSmallerThanSession() {
        testUserClientMaxLifespanSmallerThanSession(true, false);
    }

    @Test
    public void testOfflineUserClientMaxLifespanSmallerThanSessionOverrideInClient() {
        testUserClientMaxLifespanSmallerThanSession(true, true);
    }

    @Test
    public void testOfflineUserClientIdleTimeoutSmallerThanSessionNoRefresh() {
        testUserClientIdleTimeoutSmallerThanSession(0, true, false);
    }

    @Test
    public void testOfflineUserClientIdleTimeoutSmallerThanSessionOneRefresh() {
        testUserClientIdleTimeoutSmallerThanSession(1, true, false);
    }

    @Test
    public void testOnlineUserClientMaxLifespanGreaterThanSession() {
        testUserClientMaxLifespanGreaterThanSession(false, false);
    }

    @Test
    public void testOnlineUserClientMaxLifespanGreaterThanSessionOverrideInClient() {
        testUserClientMaxLifespanGreaterThanSession(false, true);
    }

    @Test
    public void testOnlineUserClientMaxLifespanSmallerThanSession() {
        testUserClientMaxLifespanSmallerThanSession(false, false);
    }

    @Test
    public void testOnlineUserClientMaxLifespanSmallerThanSessionOverrideInClient() {
        testUserClientMaxLifespanSmallerThanSession(false, true);
    }

    @Test
    public void testOnlineUserClientIdleTimeoutSmallerThanSessionNoRefresh() {
        testUserClientIdleTimeoutSmallerThanSession(0, false, false);
    }

    @Test
    public void testOnlineUserClientIdleTimeoutSmallerThanSessionOneRefresh() {
        testUserClientIdleTimeoutSmallerThanSession(1, false, false);
    }
}
