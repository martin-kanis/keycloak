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

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.session.UserSessionPersisterProvider;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author <a href="mailto:mkanis@redhat.com">Martin Kanis</a>
 */
public class MapAuthenticatedClientSessionAdapter extends AbstractAuthenticatedClientSessionModel<MapAuthenticatedClientSessionEntity> {

    public MapAuthenticatedClientSessionAdapter(KeycloakSession session, RealmModel realm, ClientModel client,
                                                UserSessionModel userSession, MapAuthenticatedClientSessionEntity entity) {
        super(session, realm, client, userSession, entity);
    }

    @Override
    public String getId() {
        return entity.getId().toString();
    }

    @Override
    public int getTimestamp() {
        return entity.getTimestamp();
    }

    @Override
    public void setTimestamp(int timestamp) {
        entity.setTimestamp(timestamp);
    }

    @Override
    public void detachFromUserSession() {
        if (this.userSession.isOffline()) {
            session.getProvider(UserSessionPersisterProvider.class).removeClientSession(userSession.getId(), client.getId(), true);
        }

        //userSession.removeAuthenticatedClientSessions(Collections.singleton(client.getId()));

        this.userSession = null;

        ((MapUserSessionProvider) session.getProvider(UserSessionProvider.class)).clientSessionTx.delete(entity.getId());
    }

    @Override
    public UserSessionModel getUserSession() {
        return userSession;
    }

    @Override
    public String getCurrentRefreshToken() {
        return entity.getCurrentRefreshToken();
    }

    @Override
    public void setCurrentRefreshToken(String currentRefreshToken) {
        entity.setCurrentRefreshToken(currentRefreshToken);
    }

    @Override
    public int getCurrentRefreshTokenUseCount() {
        return entity.getCurrentRefreshTokenUseCount();
    }

    @Override
    public void setCurrentRefreshTokenUseCount(int currentRefreshTokenUseCount) {
        entity.setCurrentRefreshTokenUseCount(currentRefreshTokenUseCount);
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
    public String getRedirectUri() {
        return entity.getRedirectUri();
    }

    @Override
    public void setRedirectUri(String uri) {
        entity.setRedirectUri(uri);
    }

    @Override
    public RealmModel getRealm() {
        return realm;
    }

    @Override
    public ClientModel getClient() {
        return client;
    }

    @Override
    public String getAction() {
        return entity.getAction();
    }

    @Override
    public void setAction(String action) {
        entity.setAction(action);
    }

    @Override
    public String getProtocol() {
        return entity.getAuthMethod();
    }

    @Override
    public void setProtocol(String method) {
        entity.setAuthMethod(method);
    }
}
