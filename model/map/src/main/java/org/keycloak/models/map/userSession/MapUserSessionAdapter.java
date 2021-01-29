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

import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.session.UserSessionPersisterProvider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:mkanis@redhat.com">Martin Kanis</a>
 */
public class MapUserSessionAdapter extends AbstractUserSessionModel<MapUserSessionEntity> {

    public MapUserSessionAdapter(KeycloakSession session, RealmModel realm, MapUserSessionEntity entity) {
        super(session, realm, entity);
    }

    @Override
    public String getId() {
        return entity.getId().toString();
    }

    @Override
    public RealmModel getRealm() {
        return realm;
    }

    @Override
    public String getBrokerSessionId() {
        return entity.getBrokerSessionId();
    }

    @Override
    public String getBrokerUserId() {
        return entity.getBrokerUserId();
    }

    @Override
    public UserModel getUser() {
        return session.users().getUserById(getRealm(), entity.getUserId());
    }

    @Override
    public String getLoginUsername() {
        return entity.getLoginUsername();
    }

    @Override
    public String getIpAddress() {
        return entity.getIpAddress();
    }

    @Override
    public String getAuthMethod() {
        return entity.getAuthMethod();
    }

    @Override
    public boolean isRememberMe() {
        return entity.isRememberMe();
    }

    @Override
    public int getStarted() {
        return entity.getStarted();
    }

    @Override
    public int getLastSessionRefresh() {
        return entity.getLastSessionRefresh();
    }

    @Override
    public void setLastSessionRefresh(int seconds) {
        if (isOffline()) {
            session.getProvider(UserSessionPersisterProvider.class).updateLastSessionRefreshes(realm, seconds,
                    Collections.singleton(entity.getId().toString()), true);
        }

        // TODO crossDC?

        entity.setLastSessionRefresh(seconds);
    }

    @Override
    public boolean isOffline() {
        return entity.isOffline();
    }

    @Override
    public AuthenticatedClientSessionModel getAuthenticatedClientSessionByClient(String clientUUID) {
        MapAuthenticatedClientSessionEntity clientSessionEntity = entity.getAuthenticatedClientSessions().get(clientUUID);

        if (clientSessionEntity == null) {
            return null;
        }

        ClientModel client = realm.getClientById(clientUUID);

        if (client != null) {
            return session.sessions().getClientSession(this, client, clientSessionEntity.getId(), isOffline());
        }

        removeAuthenticatedClientSessions(Collections.singleton(clientUUID));
        return null;
    }

    @Override
    public Map<String, AuthenticatedClientSessionModel> getAuthenticatedClientSessions() {
        Map<String, AuthenticatedClientSessionModel> result = new HashMap<>();
        List<String> removedClientUUIDS = new LinkedList<>();

        entity.getAuthenticatedClientSessions().entrySet()
                .stream()
                .forEach(entry -> {
                    String clientUUID = entry.getKey();
                    ClientModel client = realm.getClientById(clientUUID);

                    if (client != null) {
                        AuthenticatedClientSessionModel clientSession = session.sessions()
                                .getClientSession(this, client, entry.getValue().getId(), isOffline());
                        if (clientSession != null) {
                            result.put(clientUUID, clientSession);
                        }
                    } else {
                        removedClientUUIDS.add(clientUUID);
                    }
                });

        removeAuthenticatedClientSessions(removedClientUUIDS);

        return Collections.unmodifiableMap(result);
    }

    @Override
    public void removeAuthenticatedClientSessions(Collection<String> removedClientUUIDS) {
        Map<String, MapAuthenticatedClientSessionEntity> authenticatedClientSessions = entity.getAuthenticatedClientSessions();
        if (authenticatedClientSessions.isEmpty()) {
            return;
        }

        List<UUID> clientSessionUuids = removedClientUUIDS.stream()
                .map(authenticatedClientSessions::get)
                .filter(Objects::nonNull)
                .map(MapAuthenticatedClientSessionEntity::getId)
                .collect(Collectors.toList());

        MapUserSessionProvider provider = (MapUserSessionProvider) session.getProvider(UserSessionProvider.class);
        clientSessionUuids.forEach(provider.clientSessionTx::delete);

        removedClientUUIDS.forEach(clientId -> entity.updated |= (authenticatedClientSessions.remove(clientId) != null));
    }

    @Override
    public String getNote(String name) {
        return (name != null) ? entity.getNotes().get(name) : null;
    }

    @Override
    public void setNote(String name, String value) {
        if (name != null) {
            if (value == null) {
                entity.updated |= (entity.getNotes().remove(name) != null);
            } else {
                entity.updated |= (!Objects.equals(entity.getNotes().put(name, value), value));
            }
        }
    }

    @Override
    public void removeNote(String name) {
        if (name != null) {
            entity.updated |= (entity.getNotes().remove(name) != null);
        }
    }

    @Override
    public Map<String, String> getNotes() {
        return new ConcurrentHashMap<>(entity.getNotes());
    }

    @Override
    public State getState() {
        return entity.getState();
    }

    @Override
    public void setState(State state) {
        entity.setState(state);
    }

    @Override
    public void restartSession(RealmModel realm, UserModel user, String loginUsername, String ipAddress, String authMethod,
                               boolean rememberMe, String brokerSessionId, String brokerUserId) {
        entity.setRealmId(realm.getId());
        entity.setUserId(user.getId());
        entity.setLoginUsername(loginUsername);
        entity.setIpAddress(ipAddress);
        entity.setAuthMethod(authMethod);
        entity.setRememberMe(rememberMe);
        entity.setBrokerSessionId(brokerSessionId);
        entity.setBrokerUserId(brokerUserId);

        int currentTime = Time.currentTime();
        entity.setStarted(currentTime);
        entity.setLastSessionRefresh(currentTime);

        entity.setState(null);
        entity.setNotes(new ConcurrentHashMap<>());
        entity.setAuthenticatedClientSessions(new ConcurrentHashMap<>());
    }
}
