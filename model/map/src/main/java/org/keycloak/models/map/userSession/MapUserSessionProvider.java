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
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.map.common.Serialization;
import org.keycloak.models.map.storage.MapKeycloakTransaction;
import org.keycloak.models.map.storage.MapStorage;
import org.keycloak.models.map.storage.ModelCriteriaBuilder;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.keycloak.models.utils.SessionTimeoutHelper;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.common.util.StackUtil.getShortStackTrace;
import static org.keycloak.utils.StreamsUtil.paginatedStream;

/**
 * @author <a href="mailto:mkanis@redhat.com">Martin Kanis</a>
 */
public class MapUserSessionProvider implements UserSessionProvider {

    private static final Logger LOG = Logger.getLogger(MapUserSessionProvider.class);
    private final KeycloakSession session;
    protected final MapKeycloakTransaction<UUID, MapUserSessionEntity, UserSessionModel> userSessionTx;
    protected final MapKeycloakTransaction<UUID, MapAuthenticatedClientSessionEntity, AuthenticatedClientSessionModel> clientSessionTx;
    protected final MapKeycloakTransaction<UUID, MapUserLoginFailureEntity, UserLoginFailureModel> userLoginFailureTx;
    private final MapStorage<UUID, MapUserSessionEntity, UserSessionModel> userSessionStore;
    private final MapStorage<UUID, MapAuthenticatedClientSessionEntity, AuthenticatedClientSessionModel> clientSessionStore;
    private final MapStorage<UUID, MapUserLoginFailureEntity, UserLoginFailureModel> userLoginFailureStore;

    // TODO remove, use ModelCriteriaBuilder
    private static final Predicate ALWAYS_FALSE = sessionEntity -> false;

    public MapUserSessionProvider(KeycloakSession session, MapStorage<UUID, MapUserSessionEntity, UserSessionModel> userSessionStore,
                                  MapStorage<UUID, MapAuthenticatedClientSessionEntity, AuthenticatedClientSessionModel> clientSessionStore,
                                  MapStorage<UUID, MapUserLoginFailureEntity, UserLoginFailureModel> userLoginFailureStore) {
        this.session = session;
        this.userSessionStore = userSessionStore;
        this.clientSessionStore = clientSessionStore;
        this.userLoginFailureStore = userLoginFailureStore;
        userSessionTx = userSessionStore.createTransaction();
        clientSessionTx = clientSessionStore.createTransaction();
        userLoginFailureTx = userLoginFailureStore.createTransaction();

        session.getTransactionManager().enlistAfterCompletion(userSessionTx);
        session.getTransactionManager().enlistAfterCompletion(clientSessionTx);
        session.getTransactionManager().enlistAfterCompletion(userLoginFailureTx);
    }

    private BiFunction<MapUserSessionEntity, UUID, UserSessionModel> userEntityToAdapterFunc(RealmModel realm) {
        // Clone entity before returning back, to avoid giving away a reference to the live object to the caller
        return (origEntity, uuid) -> new MapUserSessionAdapter(session, realm, registerEntityForChanges(origEntity, uuid));
    }

    private Function<MapAuthenticatedClientSessionEntity, AuthenticatedClientSessionModel> clientEntityToAdapterFunc(RealmModel realm,
                                                                                                                     ClientModel client,
                                                                                                                     UserSessionModel userSession) {
        // Clone entity before returning back, to avoid giving away a reference to the live object to the caller
        return origEntity -> new MapAuthenticatedClientSessionAdapter(session, realm, client, userSession, registerEntityForChanges(origEntity));
    }

    private Function<MapUserLoginFailureEntity, UserLoginFailureModel> userLoginFailureEntityToAdapterFunc(RealmModel realm) {
        // Clone entity before returning back, to avoid giving away a reference to the live object to the caller
        return origEntity -> new MapUserLoginFailureAdapter(session, realm, registerEntityForChanges(origEntity));
    }

    private MapUserSessionEntity registerEntityForChanges(MapUserSessionEntity origEntity, UUID uuid) {
        MapUserSessionEntity res = userSessionTx.read(uuid, id -> Serialization.from(origEntity));
        userSessionTx.updateIfChanged(uuid, res, MapUserSessionEntity::isUpdated);
        return res;
    }

    private MapAuthenticatedClientSessionEntity registerEntityForChanges(MapAuthenticatedClientSessionEntity origEntity) {
        MapAuthenticatedClientSessionEntity res = clientSessionTx.read(origEntity.getId(), id -> Serialization.from(origEntity));
        clientSessionTx.updateIfChanged(origEntity.getId(), res, MapAuthenticatedClientSessionEntity::isUpdated);
        return res;
    }

    private MapUserLoginFailureEntity registerEntityForChanges(MapUserLoginFailureEntity origEntity) {
        MapUserLoginFailureEntity res = userLoginFailureTx.read(origEntity.getId(), id -> Serialization.from(origEntity));
        userLoginFailureTx.updateIfChanged(origEntity.getId(), res, MapUserLoginFailureEntity::isUpdated);
        return res;
    }

    private Predicate<MapAuthenticatedClientSessionEntity> entityClientFilter(String clientId) {
        if (clientId == null) {
            return MapUserSessionProvider.ALWAYS_FALSE;
        }
        return entity -> Objects.equals(clientId, entity.getClientId());
    }

    @Override
    public AuthenticatedClientSessionModel createClientSession(RealmModel realm, ClientModel client, UserSessionModel userSession) {
        MapAuthenticatedClientSessionEntity entity =
                new MapAuthenticatedClientSessionEntity(UUID.randomUUID(), realm.getId(), client.getId(), false);

        if (clientSessionTx.read(entity.getId()) != null) {
            throw new ModelDuplicateException("Client session exists: " + entity.getId());
        }

        clientSessionTx.create(entity.getId(), entity);

        MapUserSessionEntity userSessionEntity = userSessionTx.read(UUID.fromString(userSession.getId()));
        userSessionEntity.getAuthenticatedClientSessions().put(client.getId(), entity);

        return clientEntityToAdapterFunc(realm, client, userSession).apply(entity);
    }

    @Override
    public AuthenticatedClientSessionModel getClientSession(UserSessionModel userSession, ClientModel client,
                                                            UUID clientSessionId, boolean offline) {
        Objects.requireNonNull(userSession, "The provided user session cannot be null!");
        Objects.requireNonNull(client, "The provided client cannot be null!");
        if (clientSessionId == null) {
            return null;
        }

        LOG.tracef("getClientSession(%s, %s, %s, %s)%s", userSession.getId(), client.getId(),
                clientSessionId.toString(), offline, getShortStackTrace());

        MapAuthenticatedClientSessionEntity entity = clientSessionTx.read(clientSessionId);
        return (entity == null || !entityClientFilter(client.getId()).test(entity))
                ? null
                : clientEntityToAdapterFunc(client.getRealm(), client, userSession).apply(entity);
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
        MapUserSessionEntity entity = new MapUserSessionEntity(entityId, realm, user, loginUsername, ipAddress, authMethod, rememberMe, brokerSessionId, brokerUserId, false);

        if (userSessionTx.read(entity.getId()) != null) {
            throw new ModelDuplicateException("User session exists: " + entity.getId());
        }

        userSessionTx.create(entity.getId(), entity);

        return userEntityToAdapterFunc(realm).apply(entity, entity.getId());
    }

    @Override
    public UserSessionModel getUserSession(RealmModel realm, String id) {
        Objects.requireNonNull(realm, "The provided realm can't be null!");
        if (id == null) {
            return null;
        }

        LOG.tracef("getUserSession(%s, %s)%s", realm.getName(), id, getShortStackTrace());

        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, UUID.fromString(id));

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()))
                .findFirst()
                .orElse(null);
    }

    @Override
    public Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, UserModel user) {
        ModelCriteriaBuilder<UserSessionModel> mcb = userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, user.getId());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()));
    }

    @Override
    public Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, ClientModel client) {
        ModelCriteriaBuilder<UserSessionModel> mcb = userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()));
    }

    @Override
    public Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, ClientModel client,
                                                          Integer firstResult, Integer maxResults) {
        return paginatedStream(getUserSessionsStream(realm, client), firstResult, maxResults);
    }

    @Override
    public Stream<UserSessionModel> getUserSessionByBrokerUserIdStream(RealmModel realm, String brokerUserId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.BROKER_USER_ID, ModelCriteriaBuilder.Operator.EQ, brokerUserId);

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()));
    }

    @Override
    public UserSessionModel getUserSessionByBrokerSessionId(RealmModel realm, String brokerSessionId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.BROKER_SESSION_ID, ModelCriteriaBuilder.Operator.EQ, brokerSessionId);

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()))
                .findFirst()
                .orElse(null);
    }

    @Override
    public UserSessionModel getUserSessionWithPredicate(RealmModel realm, String id, boolean offline,
                                                        Predicate<UserSessionModel> predicate) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, offline)
                .compare(UserSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, UUID.fromString(id));

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()))
                .filter(predicate)
                .findFirst()
                .orElse(null);
    }

    @Override
    public long getActiveUserSessions(RealmModel realm, ClientModel client) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId());
        return userSessionTx.getUpdatedNotRemoved(mcb).count();
    }

    @Override
    public Map<String, Long> getActiveClientSessionStats(RealmModel realm, boolean offline) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, offline);

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(MapUserSessionEntity::getAuthenticatedClientSessions)
                .map(Map::values)
                .flatMap(Collection::stream)
                .map(MapAuthenticatedClientSessionEntity::getClientId)
                .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));
    }

    @Override
    public void removeUserSession(RealmModel realm, UserSessionModel session) {
        Objects.requireNonNull(session, "The provided user session can't be null!");

        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.ID, ModelCriteriaBuilder.Operator.EQ, UUID.fromString(session.getId()));

        userSessionTx.getUpdatedNotRemoved(mcb).forEach(userSession -> {
            userSession.getAuthenticatedClientSessions().values().stream()
                    .map(MapAuthenticatedClientSessionEntity::getId)
                    .forEach(clientSessionTx::delete);
            userSessionTx.delete(userSession.getId());
        });
    }

    @Override
    public void removeUserSessions(RealmModel realm, UserModel user) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false)
                .compare(UserSessionModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, user.getId());

        userSessionTx.getUpdatedNotRemoved(mcb).forEach(userSession -> {
            userSession.getAuthenticatedClientSessions().values().stream()
                    .map(MapAuthenticatedClientSessionEntity::getId)
                    .forEach(clientSessionTx::delete);
            userSessionTx.delete(userSession.getId());
        });
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

        Predicate<MapUserSessionEntity> filterExpired = (entity) -> {
            if (entity.isRememberMe()) {
                if (entity.getStarted() > expiredRememberMe && entity.getLastSessionRefresh() > expiredRefreshRememberMe) {
                    return false;
                }
            }
            else {
                if (entity.getStarted() > expired && entity.getLastSessionRefresh() > expiredRefresh) {
                    return false;
                }
            }

            if (entity.getLastSessionRefresh() > expiredRefresh) {
                return false;
            }
            return true;
        };

        Predicate<MapUserSessionEntity> filterExpiredOffline = (entity) -> {
            if (entity.getLastSessionRefresh() > expiredOffline) {
                return false;
            }
            return true;
        };

        Predicate<MapAuthenticatedClientSessionEntity> filterClientExpired = (entity) -> {
            if (entity.getTimestamp() > clientExpired) {
                return false;
            }

            return true;
        };

        Predicate<MapAuthenticatedClientSessionEntity> filterClientExpiredOffline = (entity) -> {
            if (entity.getTimestamp() > expiredOffline) {
                return false;
            }

            return true;
        };

        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false);
        userSessionTx.getUpdatedNotRemoved(mcb)
            .filter(filterExpired)
            .forEach(userEntity -> {
                userEntity.getAuthenticatedClientSessions().entrySet()
                        .forEach(clientEntity -> {
                            LOG.debugf("Deleting client session %s from expired user sessions %s", clientEntity.getValue().getId(), userEntity.getId());
                            clientSessionTx.delete(clientEntity.getValue().getId());
                        });
                userEntity.setAuthenticatedClientSessions(new ConcurrentHashMap<>());
                LOG.debugf("Deleting expired user sessions %s", userEntity.getId());
                userSessionTx.delete(userEntity.getId());
            });

        mcb = realmAndOfflineCriteriaBuilder(realm, true);
        userSessionTx.getUpdatedNotRemoved(mcb)
            .filter(filterExpiredOffline)
            .forEach(userEntity -> {
                userEntity.getAuthenticatedClientSessions().entrySet()
                        .forEach(clientEntity -> clientSessionTx.delete(clientEntity.getValue().getId()));
                userEntity.setAuthenticatedClientSessions(new ConcurrentHashMap<>());
                LOG.debugf("Deleting expired offline user sessions %s", userEntity.getId());
                userSessionTx.delete(userEntity.getId());
            });

        mcb = realmAndOfflineCriteriaBuilder(realm, false);
        List<MapUserSessionEntity> userSessions = userSessionTx.getUpdatedNotRemoved(mcb).collect(Collectors.toList());
        List<MapAuthenticatedClientSessionEntity> clients = userSessions.stream()
                .map(MapUserSessionEntity::getAuthenticatedClientSessions)
                .flatMap(map -> map.values().stream())
                .filter(filterClientExpired)
                .collect(Collectors.toList());

        List<String> clientUUIDs = clients.stream().map(MapAuthenticatedClientSessionEntity::getClientId).collect(Collectors.toList());
        if (!clientUUIDs.isEmpty()) {
            userSessions.stream().forEach(userSessionEntity ->
                    userSessionEntity.updated |= userSessionEntity.getAuthenticatedClientSessions().keySet().removeAll(clientUUIDs));
        }
        clients.stream().forEach(clientEntity -> {
            LOG.debugf("Deleting expired client session %s", clientEntity.getId());
            clientSessionTx.delete(clientEntity.getId());
        });

        mcb = realmAndOfflineCriteriaBuilder(realm, true);
        userSessions = userSessionTx.getUpdatedNotRemoved(mcb).collect(Collectors.toList());
        List<MapAuthenticatedClientSessionEntity> offlineClients = userSessions.stream()
                .map(MapUserSessionEntity::getAuthenticatedClientSessions)
                .flatMap(map -> map.values().stream())
                .filter(filterClientExpiredOffline)
                .collect(Collectors.toList());

        List<String> offlineClientUUIDs = offlineClients.stream().map(MapAuthenticatedClientSessionEntity::getClientId).collect(Collectors.toList());
        if (!offlineClientUUIDs.isEmpty()) {
            userSessions.stream().forEach(userSessionEntity ->
                    userSessionEntity.updated |= userSessionEntity.getAuthenticatedClientSessions().keySet().removeAll(offlineClientUUIDs));
        }
        offlineClients.stream().forEach(clientEntity -> {
            LOG.debugf("Deleting expired offline client session %s", clientEntity.getId());
            clientSessionTx.delete(clientEntity.getId());
        });

        session.getProvider(UserSessionPersisterProvider.class).removeExpired(realm);
    }

    @Override
    public void removeUserSessions(RealmModel realm) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, false);
        userSessionTx.getUpdatedNotRemoved(mcb).forEach(userSession -> {
            userSession.getAuthenticatedClientSessions().entrySet().stream().forEach(entry -> {
                clientSessionTx.delete(entry.getValue().getId());
            });
            userSessionTx.delete(userSession.getId());
        });
    }

    @Override
    public UserLoginFailureModel getUserLoginFailure(RealmModel realm, String userId) {
        ModelCriteriaBuilder<UserLoginFailureModel> mcb = userLoginFailureStore.createCriteriaBuilder()
                .compare(UserLoginFailureModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserLoginFailureModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, userId);

        return userLoginFailureTx.getUpdatedNotRemoved(mcb)
                .map(userLoginFailureEntityToAdapterFunc(realm))
                .findFirst()
                .orElse(null);
    }

    @Override
    public UserLoginFailureModel addUserLoginFailure(RealmModel realm, String userId) {
        ModelCriteriaBuilder<UserLoginFailureModel> mcb = userLoginFailureStore.createCriteriaBuilder()
                .compare(UserLoginFailureModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserLoginFailureModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, userId);

        MapUserLoginFailureEntity userLoginFailureEntity = userLoginFailureTx.getUpdatedNotRemoved(mcb).findFirst().orElse(null);

        if (userLoginFailureEntity == null) {
            userLoginFailureEntity = new MapUserLoginFailureEntity(UUID.randomUUID(), realm.getId(), userId);

            userLoginFailureTx.create(userLoginFailureEntity.getId(), userLoginFailureEntity);
        }

        return userLoginFailureEntityToAdapterFunc(realm).apply(userLoginFailureEntity);
    }

    @Override
    public void removeUserLoginFailure(RealmModel realm, String userId) {
        ModelCriteriaBuilder<UserLoginFailureModel> mcb = userLoginFailureStore.createCriteriaBuilder()
                .compare(UserLoginFailureModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserLoginFailureModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, userId);
        UUID uuid = userLoginFailureTx.getUpdatedNotRemoved(mcb).map(MapUserLoginFailureEntity::getId).findFirst().orElse(null);

        if (uuid != null) {
            // TODO Two bulk deletes within one transaction don't work. Second bulk delete will override the first bulk delete
            // expected behavior?
            userLoginFailureTx.delete(uuid);
        }
    }

    @Override
    public void removeAllUserLoginFailures(RealmModel realm) {
        ModelCriteriaBuilder<UserLoginFailureModel> mcb = userLoginFailureStore.createCriteriaBuilder()
                .compare(UserLoginFailureModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId());
        userLoginFailureTx.delete(UUID.randomUUID(), mcb);
    }

    @Override
    public void onRealmRemoved(RealmModel realm) {
        removeUserSessions(realm);
        removeAllUserLoginFailures(realm);

        UserSessionPersisterProvider sessionsPersister = session.getProvider(UserSessionPersisterProvider.class);
        if (sessionsPersister != null) {
            sessionsPersister.onRealmRemoved(realm);
        }
    }

    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {
        UserSessionPersisterProvider sessionsPersister = session.getProvider(UserSessionPersisterProvider.class);
        if (sessionsPersister != null) {
            sessionsPersister.onClientRemoved(realm, client);
        }
    }

    protected void onUserRemoved(RealmModel realm, UserModel user) {
        removeUserSessions(realm, user);

        removeUserLoginFailure(realm, user.getId());

        UserSessionPersisterProvider persisterProvider = session.getProvider(UserSessionPersisterProvider.class);
        if (persisterProvider != null) {
            persisterProvider.onUserRemoved(realm, user);
        }
    }

    @Override
    public UserSessionModel createOfflineUserSession(UserSessionModel userSession) {
        MapUserSessionEntity userSessionEntity = userSessionTx.read(UUID.fromString(userSession.getId()));

        if (userSessionEntity != null) {
            int currentTime = Time.currentTime();
            userSessionEntity.setStarted(currentTime);
            userSessionEntity.setLastSessionRefresh(currentTime);
            userSessionEntity.setOffline(true);
            userSessionEntity.setAuthenticatedClientSessions(new ConcurrentHashMap<>());
        } else {
            userSessionEntity = new MapUserSessionEntity(UUID.fromString(userSession.getId()), userSession.getRealm(), userSession.getUser(),
                    userSession.getLoginUsername(), userSession.getIpAddress(), userSession.getAuthMethod(), userSession.isRememberMe(),
                    userSession.getBrokerSessionId(), userSession.getBrokerUserId(), true);
            userSessionEntity.setNotes(new ConcurrentHashMap<>(userSession.getNotes()));
            userSessionEntity.setState(userSession.getState());
            int currentTime = Time.currentTime();
            userSessionEntity.setStarted(currentTime);
            userSessionEntity.setLastSessionRefresh(currentTime);

            userSessionTx.create(userSessionEntity.getId(), userSessionEntity);
        }

        UserSessionModel userSessionModel = userEntityToAdapterFunc(userSession.getRealm()).apply(userSessionEntity, userSessionEntity.getId());

        session.getProvider(UserSessionPersisterProvider.class).createUserSession(userSessionModel, true);

        return userSessionModel;
    }

    @Override
    public UserSessionModel getOfflineUserSession(RealmModel realm, String userSessionId) {
        return getOfflineUserSessionEntityStream(realm, userSessionId)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()))
                .findFirst()
                .orElse(null);
    }

    @Override
    public void removeOfflineUserSession(RealmModel realm, UserSessionModel userSession) {
        Objects.requireNonNull(userSession, "The provided user session can't be null!");

        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true);
        userSessionTx.getUpdatedNotRemoved(mcb)
                .filter(userEntity -> Objects.equals(userEntity.getId().toString(), userSession.getId()))
                .map(MapUserSessionEntity::getId)
                .collect(Collectors.toList())
                .forEach(userSessionTx::delete);

        session.getProvider(UserSessionPersisterProvider.class).removeUserSession(userSession.getId(), true);
    }

    @Override
    public AuthenticatedClientSessionModel createOfflineClientSession(AuthenticatedClientSessionModel clientSession,
                                                                      UserSessionModel offlineUserSession) {
        MapAuthenticatedClientSessionEntity clientSessionEntity = createAuthenticatedClientSessionInstance(clientSession, true);
        clientSessionEntity.setTimestamp(Time.currentTime());

        MapUserSessionEntity userSessionEntity = getOfflineUserSessionEntityStream(clientSession.getRealm(), offlineUserSession.getId()).findFirst().get();
        userSessionEntity.getAuthenticatedClientSessions().put(clientSession.getClient().getId(), clientSessionEntity);

        clientSessionTx.create(clientSessionEntity.getId(), clientSessionEntity);

        AuthenticatedClientSessionModel clientSessionModel = clientEntityToAdapterFunc(clientSession.getRealm(),
                clientSession.getClient(), offlineUserSession).apply(clientSessionEntity);

        session.getProvider(UserSessionPersisterProvider.class).createClientSession(clientSessionModel, true);

        return clientSessionModel;
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionsStream(RealmModel realm, UserModel user) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.USER_ID, ModelCriteriaBuilder.Operator.EQ, user.getId());

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()));
    }

    @Override
    public UserSessionModel getOfflineUserSessionByBrokerSessionId(RealmModel realm, String brokerSessionId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.BROKER_SESSION_ID, ModelCriteriaBuilder.Operator.EQ, brokerSessionId);

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()))
                .findFirst()
                .orElse(null);
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionByBrokerUserIdStream(RealmModel realm, String brokerUserId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.BROKER_USER_ID, ModelCriteriaBuilder.Operator.EQ, brokerUserId);

        return userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId()));
    }

    @Override
    public long getOfflineSessionsCount(RealmModel realm, ClientModel client) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId());
        return userSessionTx.getUpdatedNotRemoved(mcb).count();
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionsStream(RealmModel realm, ClientModel client,
                                                                 Integer firstResult, Integer maxResults) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true)
                .compare(UserSessionModel.SearchableFields.CLIENT_ID, ModelCriteriaBuilder.Operator.EQ, client.getId());
        return paginatedStream(userSessionTx.getUpdatedNotRemoved(mcb)
                .map(entity -> userEntityToAdapterFunc(realm).apply(entity, entity.getId())), firstResult, maxResults);
    }

    @Override
    public void importUserSessions(Collection<UserSessionModel> persistentUserSessions, boolean offline) {
        if (persistentUserSessions == null || persistentUserSessions.isEmpty()) {
            return;
        }

        List<MapUserSessionEntity> collect = persistentUserSessions.stream()
                .map(pus -> {
                    MapUserSessionEntity userSessionEntity = new MapUserSessionEntity(UUID.fromString(pus.getId()), pus.getRealm(), pus.getUser(),
                            pus.getLoginUsername(), pus.getIpAddress(), pus.getAuthMethod(),
                            pus.isRememberMe(), pus.getBrokerSessionId(), pus.getBrokerUserId(), offline);

                    for (Map.Entry<String, AuthenticatedClientSessionModel> entry : pus.getAuthenticatedClientSessions().entrySet()) {
                        MapAuthenticatedClientSessionEntity clientSession = toAuthenticatedClientSessionEntity(entry.getValue(), offline);

                        // Update timestamp to same value as userSession. LastSessionRefresh of userSession from DB will have correct value
                        clientSession.setTimestamp(userSessionEntity.getLastSessionRefresh());

                        Map<String, MapAuthenticatedClientSessionEntity> authenticatedClientSessions = userSessionEntity.getAuthenticatedClientSessions();
                        authenticatedClientSessions.put(entry.getKey(), clientSession);

                        clientSessionTx.create(clientSession.getId(), clientSession);
                    }

                    return userSessionEntity;
                })
                .collect(Collectors.toList());
                collect.forEach(use -> userSessionTx.create(use.getId(), use));
    }

    @Override
    public void close() {

    }

    public void removeLocalOfflineUserSessions(RealmModel realm) {
        ModelCriteriaBuilder<UserSessionModel> mcb = realmAndOfflineCriteriaBuilder(realm, true);
        List<MapUserSessionEntity> userSessions = userSessionTx.getUpdatedNotRemoved(mcb).collect(Collectors.toList());
        List<MapAuthenticatedClientSessionEntity> offlineClients = userSessions.stream()
                .map(MapUserSessionEntity::getAuthenticatedClientSessions)
                .flatMap(map -> map.values().stream())
                .collect(Collectors.toList());

        offlineClients.stream().map(MapAuthenticatedClientSessionEntity::getId).forEach(clientSessionTx::delete);
        userSessions.stream().map(MapUserSessionEntity::getId).forEach(userSessionTx::delete);
    }

    private Stream<MapUserSessionEntity> getOfflineUserSessionEntityStream(RealmModel realm, String userSessionId) {
        ModelCriteriaBuilder<UserSessionModel> mcb = userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId());

        // FIXME criteria builder for IS_OFFLINE doesn't work
        // also check criteria builder for ID
        return userSessionTx.getUpdatedNotRemoved(mcb)
                .filter(MapUserSessionEntity::isOffline)
                .filter(userEntity -> Objects.equals(userEntity.getId().toString(), userSessionId));
    }

    private ModelCriteriaBuilder<UserSessionModel> realmAndOfflineCriteriaBuilder(RealmModel realm, boolean offline) {
        return userSessionStore.createCriteriaBuilder()
                .compare(UserSessionModel.SearchableFields.REALM_ID, ModelCriteriaBuilder.Operator.EQ, realm.getId())
                .compare(UserSessionModel.SearchableFields.IS_OFFLINE, ModelCriteriaBuilder.Operator.EQ, offline);
    }

    private MapAuthenticatedClientSessionEntity toAuthenticatedClientSessionEntity(AuthenticatedClientSessionModel model, boolean offline) {
        MapAuthenticatedClientSessionEntity clientSessionEntity = new MapAuthenticatedClientSessionEntity(UUID.randomUUID(),
                model.getRealm().getId(), model.getClient().getId(), offline);
        clientSessionEntity.setAction(model.getAction());
        clientSessionEntity.setAuthMethod(model.getProtocol());

        clientSessionEntity.setNotes(model.getNotes());
        clientSessionEntity.setRedirectUri(model.getRedirectUri());
        clientSessionEntity.setTimestamp(model.getTimestamp());

        return clientSessionEntity;
    }

    private MapAuthenticatedClientSessionEntity createAuthenticatedClientSessionInstance(AuthenticatedClientSessionModel clientSession, boolean offline) {
        MapAuthenticatedClientSessionEntity entity = new MapAuthenticatedClientSessionEntity(UUID.randomUUID(),
                clientSession.getRealm().getId(), clientSession.getClient().getId(), offline);

        entity.setAction(clientSession.getAction());
        entity.setAuthMethod(clientSession.getProtocol());

        entity.setNotes(new ConcurrentHashMap<>(clientSession.getNotes()));
        entity.setRedirectUri(clientSession.getRedirectUri());
        entity.setTimestamp(clientSession.getTimestamp());

        return entity;
    }
}
