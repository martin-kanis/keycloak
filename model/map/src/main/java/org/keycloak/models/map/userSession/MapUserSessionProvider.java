/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.models.map.userSession;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.device.DeviceActivityManager;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.map.common.Serialization;
import org.keycloak.models.map.storage.MapKeycloakTransaction;
import org.keycloak.models.map.storage.MapStorage;
import org.keycloak.models.map.storage.ModelCriteriaBuilder;
import org.keycloak.models.utils.SessionTimeoutHelper;

import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.common.util.StackUtil.getShortStackTrace;
import static org.keycloak.models.UserSessionModel.SessionPersistenceState.TRANSIENT;
import static org.keycloak.utils.StreamsUtil.paginatedStream;

/**
 * @author <a href="mailto:mkanis@redhat.com">Martin Kanis</a>
 */
public class MapUserSessionProvider implements UserSessionProvider {

    private static final Logger LOG = Logger.getLogger(MapUserSessionProvider.class);
    private final KeycloakSession session;
    protected final MapKeycloakTransaction<UUID, MapUserSessionEntity, UserSessionModel> userSessionTx;
    protected final MapKeycloakTransaction<UUID, MapAuthenticatedClientSessionEntity, AuthenticatedClientSessionModel> clientSessionTx;
    private final MapStorage<UUID, MapUserSessionEntity, UserSessionModel> userSessionStore;
    private final MapStorage<UUID, MapAuthenticatedClientSessionEntity, AuthenticatedClientSessionModel> clientSessionStore;

    /**
     * Storage for transient user sessions which lifespan is limited to one request.
     */
    private Map<UUID, MapUserSessionEntity> transientUserSessions = new HashMap<>();

    public MapUserSessionProvider(KeycloakSession session, MapStorage<UUID, MapUserSessionEntity, UserSessionModel> userSessionStore,
                                  MapStorage<UUID, MapAuthenticatedClientSessionEntity, AuthenticatedClientSessionModel> clientSessionStore) {
        this.session = session;
        this.userSessionStore = userSessionStore;
        this.clientSessionStore = clientSessionStore;
        userSessionTx = userSessionStore.createTransaction(session);
        clientSessionTx = clientSessionStore.createTransaction(session);

        session.getTransactionManager().enlistAfterCompletion(userSessionTx);
        session.getTransactionManager().enlistAfterCompletion(clientSessionTx);
    }

    private Function<MapUserSessionEntity, UserSessionModel> userEntityToAdapterFunc(RealmModel realm) {
        // Clone entity before returning back, to avoid giving away a reference to the live object to the caller
        return (origEntity) -> new MapUserSessionAdapter(session, realm,
                Objects.equals(origEntity.getPersistenceState(), TRANSIENT) ? origEntity : registerEntityForChanges(origEntity)) {

            @Override
            public void removeAuthenticatedClientSessions(Collection<String> removedClientUUIDS) {
                removedClientUUIDS.forEach(clientId -> {
                    clientSessionTx.delete(UUID.fromString(clientId));
                    entity.removeAuthenticatedClientSession(clientId);
                });
            }
        };
    }

    private Function<MapAuthenticatedClientSessionEntity, AuthenticatedClientSessionModel> clientEntityToAdapterFunc(RealmModel realm,
                                                                                                                     ClientModel client,
                                                                                                                     UserSessionModel userSession) {
        // Clone entity before returning back, to avoid giving away a reference to the live object to the caller
        return origEntity -> new MapAuthenticatedClientSessionAdapter(session, realm, client, userSession, registerEntityForChanges(origEntity)) {
            @Override
            public void detachFromUserSession() {
                this.userSession = null;

                clientSessionTx.delete(entity.getId());
            }
        };
    }

    private MapUserSessionEntity registerEntityForChanges(MapUserSessionEntity origEntity) {
        MapUserSessionEntity res = userSessionTx.read(origEntity.getId(), id -> Serialization.from(origEntity));
        userSessionTx.updateIfChanged(origEntity.getId(), res, MapUserSessionEntity::isUpdated);
        return res;
    }

    private MapAuthenticatedClientSessionEntity registerEntityForChanges(MapAuthenticatedClientSessionEntity origEntity) {
        MapAuthenticatedClientSessionEntity res = clientSessionTx.read(origEntity.getId(), id -> Serialization.from(origEntity));
        clientSessionTx.updateIfChanged(origEntity.getId(), res, MapAuthenticatedClientSessionEntity::isUpdated);
        return res;
    }

    @Override
    public KeycloakSession getKeycloakSession() {
        return session;
    }

    @Override
    public AuthenticatedClientSessionModel createClientSession(RealmModel realm, ClientModel client, UserSessionModel userSession) {
        MapAuthenticatedClientSessionEntity entity =
                new MapAuthenticatedClientSessionEntity(UUID.randomUUID(), userSession.getId(), realm.getId(), client.getId(), false);

        LOG.tracef("createClientSession(%s, %s, %s)%s", realm, client, userSession, getShortStackTrace());

        clientSessionTx.create(entity.getId(), entity);

        MapUserSessionEntity userSessionEntity = getUserSessionById(UUID.fromString(userSession.getId()));

        if (userSessionEntity == null) {
            throw new IllegalStateException("User session entity does not exist: " + userSession.getId());
        }

        userSessionEntity.addAuthenticatedClientSession(client.getId(), entity.getId());

        return clientEntityToAdapterFunc(realm, client, userSession).apply(entity);
    }

    @Override
    public AuthenticatedClientSessionModel getClientSession(UserSessionModel userSession, ClientModel client,
                                                            UUID clientSessionId, boolean offline) {
        LOG.tracef("getClientSession(%s, %s, %s, %s)%s", userSession, client,
                clientSessionId, offline, getShortStackTrace());

        Objects.requireNonNull(userSession, "The provided user session cannot be null!");
        Objects.requireNonNull(client, "The provided client cannot be null!");
        if (clientSessionId == null) {
            return null;
        }

        ModelCriteriaBuilder<AuthenticatedClientSessionModel> mcb = clientSessionStore.createCriteriaBuilder()
                .compare(AuthenticatedClientSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, clientSessionId)
                .compare(AuthenticatedClientSessionModel.SearchableFields.USER_SESSION_ID, ModelCriteriaBuilder.Operator.EQ, userSession.getId())
                .compare(AuthenticatedClientSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, userSession.getRealm().getId())
                .compare(AuthenticatedClientSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId())
                .compare(AuthenticatedClientSessionModel.SearchableFields.IS_OFFLINE, ModelCriteriaBuilder.Operator.EQ, offline);

        return clientSessionTx.getUpdatedNotRemoved(mcb)
                .map(clientEntityToAdapterFunc(client.getRealm(), client, userSession))
                .findFirst()
                .orElse(null);
    }

    @Override
    public UserSessionModel createUserSession(RealmModel realm, UserModel user, String loginUsername, String ipAddress,
                                              String authMethod, boolean rememberMe, String brokerSessionId, String brokerUserId) {
        return createUserSession(null, realm, user, loginUsername, ipAddress, authMethod, rememberMe, brokerSessionId,
                brokerUserId, UserSessionModel.SessionPersistenceState.PERSISTENT);
    }

    @Override
    public UserSessionModel createUserSession(String id, RealmModel realm, UserModel user, String loginUsername,
                                              String ipAddress, String authMethod, boolean rememberMe, String brokerSessionId,
                                              String brokerUserId, UserSessionModel.SessionPersistenceState persistenceState) {
        final UUID entityId = id == null ? UUID.randomUUID() : UUID.fromString(id);

        LOG.tracef("createUserSession(%s, %s, %s, %s)%s", id, realm, loginUsername, persistenceState, getShortStackTrace());

        MapUserSessionEntity entity = new MapUserSessionEntity(entityId, realm, user, loginUsername, ipAddress, authMethod, rememberMe, brokerSessionId, brokerUserId, false);
        entity.setPersistenceState(persistenceState);

        if (Objects.equals(persistenceState, TRANSIENT)) {
            transientUserSessions.put(entityId, entity);
        } else {
            if (userSessionTx.read(entity.getId()) != null) {
                throw new ModelDuplicateException("User session exists: " + entity.getId());
            }

            userSessionTx.create(entity.getId(), entity);
        }

        UserSessionModel userSession = userEntityToAdapterFunc(realm).apply(entity);

        DeviceActivityManager.attachDevice(userSession, session);

        return userSession;
    }

    @Override
    public UserSessionModel getUserSession(RealmModel realm, String id) {
        Objects.requireNonNull(realm, "The provided realm can't be null!");

        LOG.tracef("getUserSession(%s, %s)%s", realm, id, getShortStackTrace());

        UUID uuid = toUUID(id);
        if (uuid == null) {
            return null;
        }

        MapUserSessionEntity userSessionEntity = transientUserSessions.get(uuid);
        if (userSessionEntity != null) {
            return userEntityToAdapterFunc(realm).apply(userSessionEntity);
        }

        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, uuid);

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm))
                .findFirst()
                .orElse(null);
    }

    @Override
    public Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, UserModel user) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, user.getId());

        LOG.tracef("getUserSessionsStream(%s, %s)%s", realm, user, getShortStackTrace());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm));
    }

    @Override
    public Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, ClientModel client) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId());

        LOG.tracef("getUserSessionsStream(%s, %s)%s", realm, client, getShortStackTrace());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm));
    }

    @Override
    public Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, ClientModel client,
                                                          Integer firstResult, Integer maxResults) {
        return paginatedStream(getUserSessionsStream(realm, client)
                .sorted(Comparator.comparing(UserSessionModel::getLastSessionRefresh)), firstResult, maxResults);
    }

    @Override
    public Stream<UserSessionModel> getUserSessionByBrokerUserIdStream(RealmModel realm, String brokerUserId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.BROKER_USER_ID, ModelCriteriaBuilder.Operator.EQ, brokerUserId);

        LOG.tracef("getUserSessionByBrokerUserIdStream(%s, %s)%s", realm, brokerUserId, getShortStackTrace());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm));
    }

    @Override
    public UserSessionModel getUserSessionByBrokerSessionId(RealmModel realm, String brokerSessionId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.BROKER_SESSION_ID, ModelCriteriaBuilder.Operator.EQ, brokerSessionId);

        LOG.tracef("getUserSessionByBrokerSessionId(%s, %s)%s", realm, brokerSessionId, getShortStackTrace());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm))
                .findFirst()
                .orElse(null);
    }

    @Override
    public UserSessionModel getUserSessionWithPredicate(RealmModel realm, String id, boolean offline,
                                                        Predicate<UserSessionModel> predicate) {
        LOG.tracef("getUserSessionWithPredicate(%s, %s, %s)%s", realm, id, offline, getShortStackTrace());

        Stream<UserSessionModel> userSessionEntityStream;
        if (offline) {
            userSessionEntityStream = getOfflineUserSessionEntityStream(realm, id)
                    .map(userEntityToAdapterFunc(realm));
        } else {
            UserSessionModel userSession = getUserSession(realm, id);
            userSessionEntityStream = userSession != null ? Stream.of(userSession) : Stream.empty();
        }

        return userSessionEntityStream
                .filter(predicate)
                .findFirst()
                .orElse(null);
    }

    @Override
    public long getActiveUserSessions(RealmModel realm, ClientModel client) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId());

        LOG.tracef("getActiveUserSessions(%s, %s)%s", realm, client, getShortStackTrace());

        return userSessionTx.getCount(mcb);
    }

    @Override
    public Map<String, Long> getActiveClientSessionStats(RealmModel realm, boolean offline) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, offline);

        LOG.tracef("getActiveClientSessionStats(%s, %s)%s", realm, offline, getShortStackTrace());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(MapUserSessionEntity::getAuthenticatedClientSessions)
                .map(Map::keySet)
                .flatMap(Collection::stream)
                .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));
    }

    @Override
    public void removeUserSession(RealmModel realm, UserSessionModel session) {
        Objects.requireNonNull(session, "The provided user session can't be null!");

        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, UUID.fromString(session.getId()));

        LOG.tracef("removeUserSession(%s, %s)%s", realm, session, getShortStackTrace());

        List<String> userSessions = userSessionTx.getUpdatedNotRemoved(mcb).map(MapUserSessionEntity::getId).map(UUID::toString).collect(Collectors.toList());
        ModelCriteriaBuilder<AuthenticatedClientSessionModel> clientSessionMcb = clientSessionStore.createCriteriaBuilder()
                .compare(AuthenticatedClientSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(AuthenticatedClientSessionModel.SearchableFields.USER_SESSION_ID, ModelCriteriaBuilder.Operator.IN, userSessions);
        clientSessionTx.delete(UUID.randomUUID(), clientSessionMcb);
        // TODO
        //userSessionTx.delete(UUID.randomUUID(), mcb);
        userSessions.stream().map(UUID::fromString).forEach(userSessionTx::delete);
    }

    @Override
    public void removeUserSessions(RealmModel realm, UserModel user) {
        ModelCriteriaBuilder<UserSessionModel> mcb = userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, user.getId());

        LOG.tracef("removeUserSessions(%s, %s)%s", realm, user, getShortStackTrace());

        List<String> userSessions = userSessionTx.getUpdatedNotRemoved(mcb).map(MapUserSessionEntity::getId).map(UUID::toString).collect(Collectors.toList());
        ModelCriteriaBuilder<AuthenticatedClientSessionModel> clientSessionMcb = clientSessionStore.createCriteriaBuilder()
                .compare(AuthenticatedClientSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(AuthenticatedClientSessionModel.SearchableFields.USER_SESSION_ID, ModelCriteriaBuilder.Operator.IN, userSessions);
        clientSessionTx.delete(UUID.randomUUID(), clientSessionMcb);
        // TODO
        //userSessionTx.delete(UUID.randomUUID(), mcb);
        userSessions.stream().map(UUID::fromString).forEach(userSessionTx::delete);
    }

    @Override
    public void removeAllExpired() {
        session.realms().getRealmsStream().forEach(this::removeExpired);
    }

    @Override
    public void removeExpired(RealmModel realm) {
        int currentTime = Time.currentTime();
        int expired = currentTime - realm.getSsoSessionMaxLifespan();
        int expiredRefresh = currentTime - realm.getSsoSessionIdleTimeout() - SessionTimeoutHelper.PERIODIC_CLEANER_IDLE_TIMEOUT_WINDOW_SECONDS;
        int expiredRememberMe = currentTime - (realm.getSsoSessionMaxLifespanRememberMe() > 0 ?
                realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan());
        int expiredRefreshRememberMe = currentTime - (realm.getSsoSessionIdleTimeoutRememberMe() > 0 ?
                realm.getSsoSessionIdleTimeoutRememberMe() : realm.getSsoSessionIdleTimeout()) -
                SessionTimeoutHelper.PERIODIC_CLEANER_IDLE_TIMEOUT_WINDOW_SECONDS;
        int expiredOffline = currentTime - realm.getOfflineSessionIdleTimeout() - SessionTimeoutHelper.PERIODIC_CLEANER_IDLE_TIMEOUT_WINDOW_SECONDS;
        int clientExpired = Math.min(expired, expiredRememberMe);

        // remove expired user sessions and its client sessions
        ModelCriteriaBuilder<UserSessionModel> userSessionMcb = userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.IS_EXPIRED, ModelCriteriaBuilder.Operator.EQ,
                        expiredRememberMe, expiredRefreshRememberMe, expired, expiredRefresh, expiredOffline);

        List<String> userSessions = userSessionTx.getUpdatedNotRemoved(userSessionMcb).map(MapUserSessionEntity::getId).map(UUID::toString).collect(Collectors.toList());

        userSessionTx.delete(UUID.randomUUID(), userSessionMcb);

        // remove expired client sessions just from the map store
        // the client sessions will be removed lazily from corresponding user sessions when demanded in MapUserSessionAdapter.getAuthenticatedClientSessions
        ModelCriteriaBuilder<AuthenticatedClientSessionModel> clientSessionMcb = clientSessionStore.createCriteriaBuilder()
                .compare(AuthenticatedClientSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .and(clientSessionStore.createCriteriaBuilder().or(
                        clientSessionStore.createCriteriaBuilder().compare(AuthenticatedClientSessionModel.SearchableFields.USER_SESSION_ID, ModelCriteriaBuilder.Operator.IN, userSessions),
                        clientSessionStore.createCriteriaBuilder().compare(AuthenticatedClientSessionModel.SearchableFields.IS_EXPIRED, ModelCriteriaBuilder.Operator.EQ, clientExpired, expiredOffline)
                        )
                );
        clientSessionTx.delete(UUID.randomUUID(), clientSessionMcb);
    }

    @Override
    public void removeUserSessions(RealmModel realm) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false);

        LOG.tracef("removeUserSessions(%s)%s", realm, getShortStackTrace());

        List<String> userSessions = userSessionTx.getUpdatedNotRemoved(mcb).map(MapUserSessionEntity::getId).map(UUID::toString).collect(Collectors.toList());
        ModelCriteriaBuilder<AuthenticatedClientSessionModel> clientSessionMcb = clientSessionStore.createCriteriaBuilder()
                .compare(AuthenticatedClientSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(AuthenticatedClientSessionModel.SearchableFields.USER_SESSION_ID, ModelCriteriaBuilder.Operator.IN, userSessions);
        clientSessionTx.delete(UUID.randomUUID(), clientSessionMcb);
        // TODO
        //userSessionTx.delete(UUID.randomUUID(), mcb);
        userSessions.stream().map(UUID::fromString).forEach(userSessionTx::delete);
    }

    @Override
    public void onRealmRemoved(RealmModel realm) {
        removeUserSessions(realm);
        session.loginFailures().removeAllUserLoginFailures(realm);
    }

    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {

    }

    protected void onUserRemoved(RealmModel realm, UserModel user) {
        removeUserSessions(realm, user);

        session.loginFailures().removeUserLoginFailure(realm, user.getId());
    }

    @Override
    public UserSessionModel createOfflineUserSession(UserSessionModel userSession) {
        LOG.tracef("createOfflineUserSession(%s)%s", userSession, getShortStackTrace());

        MapUserSessionEntity offlineUserSession = createUserSessionEntityInstance(userSession, true);

        // set a reference for the offline user session in the original online user session
        ((MapUserSessionAdapter) userSession).setCorrespondingSessionId(offlineUserSession.getId());
        int currentTime = Time.currentTime();
        offlineUserSession.setStarted(currentTime);
        offlineUserSession.setLastSessionRefresh(currentTime);

        userSessionTx.create(offlineUserSession.getId(), offlineUserSession);

        return userEntityToAdapterFunc(userSession.getRealm()).apply(offlineUserSession);
    }

    @Override
    public UserSessionModel getOfflineUserSession(RealmModel realm, String userSessionId) {
        LOG.tracef("getOfflineUserSession(%s, %s)%s", realm, userSessionId, getShortStackTrace());

        return getOfflineUserSessionEntityStream(realm, userSessionId)
                .map(userEntityToAdapterFunc(realm))
                .findFirst()
                .orElse(null);
    }

    @Override
    public void removeOfflineUserSession(RealmModel realm, UserSessionModel userSession) {
        Objects.requireNonNull(userSession, "The provided user session can't be null!");

        LOG.tracef("removeOfflineUserSession(%s, %s)%s", realm, userSession, getShortStackTrace());

        ModelCriteriaBuilder<UserSessionModel> mcb;
        if (userSession.isOffline()) {
            userSessionTx.delete(UUID.fromString(userSession.getId()));
        } else {
            MapUserSessionAdapter onlineUserSession = (MapUserSessionAdapter) userSession;

            if (onlineUserSession.getCorrespondingSessionId() != null) {
                mcb = realmAndOfflineCriteriaBuilder(realm, true)
                        .compare(UserSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, onlineUserSession.getCorrespondingSessionId());
                userSessionTx.delete(UUID.randomUUID(), mcb);
                onlineUserSession.setCorrespondingSessionId(null);
            }
        }
    }

    @Override
    public AuthenticatedClientSessionModel createOfflineClientSession(AuthenticatedClientSessionModel clientSession,
                                                                      UserSessionModel offlineUserSession) {
        LOG.tracef("createOfflineClientSession(%s, %s)%s", clientSession, offlineUserSession, getShortStackTrace());

        MapAuthenticatedClientSessionEntity clientSessionEntity = createAuthenticatedClientSessionInstance(clientSession, offlineUserSession, true);
        clientSessionEntity.setTimestamp(Time.currentTime());

        Optional<MapUserSessionEntity> userSessionEntity = getOfflineUserSessionEntityStream(clientSession.getRealm(), offlineUserSession.getId()).findFirst();
        if (userSessionEntity.isPresent()) {
            userSessionEntity.get().addAuthenticatedClientSession(clientSession.getClient().getId(), clientSessionEntity.getId());
        }

        clientSessionTx.create(clientSessionEntity.getId(), clientSessionEntity);

        return clientEntityToAdapterFunc(clientSession.getRealm(),
                clientSession.getClient(), offlineUserSession).apply(clientSessionEntity);
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionsStream(RealmModel realm, UserModel user) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, user.getId());

        LOG.tracef("getOfflineUserSessionsStream(%s, %s)%s", realm, user, getShortStackTrace());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm));
    }

    @Override
    public UserSessionModel getOfflineUserSessionByBrokerSessionId(RealmModel realm, String brokerSessionId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.BROKER_SESSION_ID, ModelCriteriaBuilder.Operator.EQ, brokerSessionId);

        LOG.tracef("getOfflineUserSessionByBrokerSessionId(%s, %s)%s", realm, brokerSessionId, getShortStackTrace());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm))
                .findFirst()
                .orElse(null);
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionByBrokerUserIdStream(RealmModel realm, String brokerUserId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.BROKER_USER_ID, ModelCriteriaBuilder.Operator.EQ, brokerUserId);

        LOG.tracef("getOfflineUserSessionByBrokerUserIdStream(%s, %s)%s", realm, brokerUserId, getShortStackTrace());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm));
    }

    @Override
    public long getOfflineSessionsCount(RealmModel realm, ClientModel client) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId());

        LOG.tracef("getOfflineSessionsCount(%s, %s)%s", realm, client, getShortStackTrace());

        return userSessionTx.getCount(mcb);
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionsStream(RealmModel realm, ClientModel client,
                                                                 Integer firstResult, Integer maxResults) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId());

        LOG.tracef("getOfflineUserSessionsStream(%s, %s, %s, %s)%s", realm, client, firstResult, maxResults, getShortStackTrace());

        return paginatedStream(userSessionTx.getUpdatedNotRemoved(mcb)
                .map(userEntityToAdapterFunc(realm))
                .sorted(Comparator.comparing(UserSessionModel::getLastSessionRefresh)), firstResult, maxResults);
    }

    @Override
    public void importUserSessions(Collection<UserSessionModel> persistentUserSessions, boolean offline) {
        if (persistentUserSessions == null || persistentUserSessions.isEmpty()) {
            return;
        }

        persistentUserSessions.stream()
            .map(pus -> {
                MapUserSessionEntity userSessionEntity = new MapUserSessionEntity(UUID.randomUUID(), pus.getRealm(), pus.getUser(),
                        pus.getLoginUsername(), pus.getIpAddress(), pus.getAuthMethod(),
                        pus.isRememberMe(), pus.getBrokerSessionId(), pus.getBrokerUserId(), offline);

                for (Map.Entry<String, AuthenticatedClientSessionModel> entry : pus.getAuthenticatedClientSessions().entrySet()) {
                    MapAuthenticatedClientSessionEntity clientSession = createAuthenticatedClientSessionInstance(entry.getValue(), entry.getValue().getUserSession(), offline);

                    // Update timestamp to same value as userSession. LastSessionRefresh of userSession from DB will have correct value
                    clientSession.setTimestamp(userSessionEntity.getLastSessionRefresh());

                    userSessionEntity.addAuthenticatedClientSession(entry.getKey(), clientSession.getId());

                    clientSessionTx.create(clientSession.getId(), clientSession);
                }

                return userSessionEntity;
            })
            .forEach(use -> userSessionTx.create(use.getId(), use));
    }

    @Override
    public void close() {

    }

    private Stream<MapUserSessionEntity> getOfflineUserSessionEntityStream(RealmModel realm, String userSessionId) {
        UUID uuid = toUUID(userSessionId);
        if (uuid == null) {
            return Stream.empty();
        }

        // first get a user entity by ID
        ModelCriteriaBuilder<UserSessionModel> mcb = userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, uuid);

        // check if it's an offline user session
        MapUserSessionEntity userSessionEntity = userSessionTx.getUpdatedNotRemoved(mcb).findFirst().orElse(null);
        if (userSessionEntity != null) {
            if (userSessionEntity.isOffline()) {
                return Stream.of(userSessionEntity);
            }
        } else {
            // no session found by the given ID, try to find by corresponding session ID
            mcb = realmAndOfflineCriteriaBuilder(realm, true)
                    .compare(UserSessionModel.SearchableFields.CORRESPONDING_SESSION_ID, ModelCriteriaBuilder.Operator.EQ, uuid);
            return userSessionTx.getUpdatedNotRemoved(mcb);
        }

        // it's online user session so lookup offline user session by corresponding session reference
        mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, userSessionEntity.getCorrespondingSessionId());
        return userSessionTx.getUpdatedNotRemoved(mcb);
    }

    private ModelCriteriaBuilder<UserSessionModel> realmAndOfflineCriteriaBuilder(RealmModel realm, boolean offline) {
        return userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.IS_OFFLINE, ModelCriteriaBuilder.Operator.EQ, offline);
    }

    private MapUserSessionEntity getUserSessionById(UUID id) {
        MapUserSessionEntity userSessionEntity = transientUserSessions.get(id);

        if (userSessionEntity == null) {
            MapUserSessionEntity userSession = userSessionTx.read(id);
            return userSession != null ? registerEntityForChanges(userSession) : null;
        }
        return userSessionEntity;
    }

    private MapUserSessionEntity createUserSessionEntityInstance(UserSessionModel userSession, boolean offline) {
        MapUserSessionEntity entity = new MapUserSessionEntity(UUID.randomUUID(), userSession.getRealm().getId());
        entity.setCorrespondingSessionId(UUID.fromString(userSession.getId()));

        entity.setAuthMethod(userSession.getAuthMethod());
        entity.setBrokerSessionId(userSession.getBrokerSessionId());
        entity.setBrokerUserId(userSession.getBrokerUserId());
        entity.setIpAddress(userSession.getIpAddress());
        entity.setNotes(new ConcurrentHashMap<>(userSession.getNotes()));
        entity.clearAuthenticatedClientSessions();
        entity.setRememberMe(userSession.isRememberMe());
        entity.setState(userSession.getState());
        entity.setLoginUsername(userSession.getLoginUsername());
        entity.setUserId(userSession.getUser().getId());

        entity.setStarted(userSession.getStarted());
        entity.setLastSessionRefresh(userSession.getLastSessionRefresh());
        entity.setOffline(offline);

        return entity;
    }

    private MapAuthenticatedClientSessionEntity createAuthenticatedClientSessionInstance(AuthenticatedClientSessionModel clientSession,
                                                                                         UserSessionModel userSession, boolean offline) {
        MapAuthenticatedClientSessionEntity entity = new MapAuthenticatedClientSessionEntity(UUID.randomUUID(),
                userSession.getId(), clientSession.getRealm().getId(), clientSession.getClient().getId(), offline);

        entity.setAction(clientSession.getAction());
        entity.setAuthMethod(clientSession.getProtocol());

        entity.setNotes(new ConcurrentHashMap<>(clientSession.getNotes()));
        entity.setRedirectUri(clientSession.getRedirectUri());
        entity.setTimestamp(clientSession.getTimestamp());

        return entity;
    }

    private UUID toUUID(String id) {
        try {
            return UUID.fromString(id);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}
