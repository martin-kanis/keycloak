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
import org.keycloak.models.map.common.AbstractEntity;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author <a href="mailto:mkanis@redhat.com">Martin Kanis</a>
 */
public abstract class AbstractAuthenticatedClientSessionEntity<K> implements AbstractEntity<K> {

    private K id;
    private String userSessionId;
    private String realmId;
    private String clientId;

    /**
     * Flag signalizing that any of the setters has been meaningfully used.
     */
    protected boolean updated;

    private String authMethod;
    private String redirectUri;
    private volatile int timestamp;
    private String action;

    private Map<String, String> notes = new ConcurrentHashMap<>();

    private String currentRefreshToken;
    private int currentRefreshTokenUseCount;

    private boolean offline;

    public AbstractAuthenticatedClientSessionEntity() {
        this.id = null;
        this.realmId = null;
    }

    public AbstractAuthenticatedClientSessionEntity(K id, String userSessionId, String realmId, String clientId, boolean offline) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(userSessionId, "userSessionId");
        Objects.requireNonNull(realmId, "realmId");
        Objects.requireNonNull(clientId, "clientId");

        this.id = id;
        this.userSessionId = userSessionId;
        this.realmId = realmId;
        this.clientId = clientId;
        this.offline = offline;
        this.timestamp = Time.currentTime();
    }

    @Override
    public K getId() {
        return this.id;
    }

    @Override
    public boolean isUpdated() {
        return this.updated;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.updated |= !Objects.equals(this.realmId, realmId);
        this.realmId = realmId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.updated |= !Objects.equals(this.clientId, clientId);
        this.clientId = clientId;
    }

    public String getUserSessionId() {
        return userSessionId;
    }

    public void setUserSessionId(String userSessionId) {
        this.updated |= !Objects.equals(this.userSessionId, userSessionId);
        this.userSessionId = userSessionId;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.updated |= !Objects.equals(this.authMethod, authMethod);
        this.authMethod = authMethod;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.updated |= !Objects.equals(this.redirectUri, redirectUri);
        this.redirectUri = redirectUri;
    }

    public int getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(int timestamp) {
        this.updated |= this.timestamp != timestamp;
        this.timestamp = timestamp;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.updated |= !Objects.equals(this.action, action);
        this.action = action;
    }

    public Map<String, String> getNotes() {
        return notes;
    }

    public void setNotes(Map<String, String> notes) {
        this.updated |= !Objects.equals(this.notes, notes);
        this.notes = notes;
    }

    public String removeNote(String name) {
        String note = this.notes.remove(name);
        this.updated |= note != null;
        return note;
    }

    public void addNote(String name, String value) {
        this.updated |= !Objects.equals(this.notes.put(name, value), value);
    }

    public String getCurrentRefreshToken() {
        return currentRefreshToken;
    }

    public void setCurrentRefreshToken(String currentRefreshToken) {
        this.updated |= !Objects.equals(this.currentRefreshToken, currentRefreshToken);
        this.currentRefreshToken = currentRefreshToken;
    }

    public int getCurrentRefreshTokenUseCount() {
        return currentRefreshTokenUseCount;
    }

    public void setCurrentRefreshTokenUseCount(int currentRefreshTokenUseCount) {
        this.updated |= this.currentRefreshTokenUseCount != currentRefreshTokenUseCount;
        this.currentRefreshTokenUseCount = currentRefreshTokenUseCount;
    }

    public boolean isOffline() {
        return offline;
    }

    public void setOffline(boolean offline) {
        this.updated |= this.offline != offline;
        this.offline = offline;
    }
}
