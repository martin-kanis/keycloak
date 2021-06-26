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
package org.keycloak.testsuite.model;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.RoleModel;
import org.keycloak.models.RoleProvider;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 *
 * @author rmartinc
 */
@RequireProvider(RealmProvider.class)
@RequireProvider(ClientProvider.class)
@RequireProvider(RoleProvider.class)
public class ClientModelTest extends KeycloakModelTest {

    private String realmId;

    @Override
    public void createEnvironment(KeycloakSession s) {
        RealmModel realm = s.realms().createRealm("realm");
        realm.setDefaultRole(s.roles().addRealmRole(realm, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realm.getName()));
        this.realmId = realm.getId();
    }

    @Override
    public void cleanEnvironment(KeycloakSession s) {
        s.realms().removeRealm(realmId);
    }

    @Test
    public void testClientsBasics() {
        // Create client
        ClientModel originalModel = withRealm(realmId, (session, realm) -> session.clients().addClient(realm, "myClientId"));
        assertThat(originalModel.getId(), notNullValue());

        // Find by id
        {
            ClientModel model = withRealm(realmId, (session, realm) -> session.clients().getClientById(realm, originalModel.getId()));
            assertThat(model, notNullValue());
            assertThat(model.getId(), is(equalTo(model.getId())));
            assertThat(model.getClientId(), is(equalTo("myClientId")));
        }

        // Find by clientId
        {
            ClientModel model = withRealm(realmId, (session, realm) -> session.clients().getClientByClientId(realm, "myClientId"));
            assertThat(model, notNullValue());
            assertThat(model.getId(), is(equalTo(originalModel.getId())));
            assertThat(model.getClientId(), is(equalTo("myClientId")));
        }

        // Test attributes
        {
            // Add some attributes
            withRealm(realmId, (session, realm) -> {
                ClientModel clientById = session.clients().getClientById(realm, originalModel.getId());
                clientById.setAttribute("attribute1", "myAttributeValue");
                return clientById;
            });

            List<ClientModel> attribute1 = withRealm(realmId, (session, realm) -> session.clients().searchClientsByAttributes(realm, Collections.singletonMap("attribute1", "myAttributeValue"), null, null)).collect(Collectors.toList());
            assertThat(attribute1, hasSize(1));

            List<ClientModel> attribute2 = withRealm(realmId, (session, realm) -> session.clients().searchClientsByAttributes(realm, Collections.singletonMap("attribute2", ""), null, null)).collect(Collectors.toList());
            assertThat(attribute2, hasSize(0));
        }
    }

    @Test
    public void testScopeMappingRoleRemoval() {
        // create two clients, one realm role and one client role and assign both to one of the clients
        inComittedTransaction(1, (session , i) -> {
            final RealmModel realm = session.realms().getRealm(realmId);
            ClientModel client1 = session.clients().addClient(realm, "client1");
            ClientModel client2 = session.clients().addClient(realm, "client2");
            RoleModel realmRole = session.roles().addRealmRole(realm, "realm-role");
            RoleModel client2Role = session.roles().addClientRole(client2, "client2-role");
            client1.addScopeMapping(realmRole);
            client1.addScopeMapping(client2Role);
            return null;
        });

        // check everything is OK
        inComittedTransaction(1, (session, i) -> {
            final RealmModel realm = session.realms().getRealm(realmId);
            final ClientModel client1 = session.clients().getClientByClientId(realm, "client1");
            assertThat(client1.getScopeMappingsStream().count(), is(2L));
            assertThat(client1.getScopeMappingsStream().filter(r -> r.getName().equals("realm-role")).count(), is(1L));
            assertThat(client1.getScopeMappingsStream().filter(r -> r.getName().equals("client2-role")).count(), is(1L));
            return null;
        });

        // remove the realm role
        inComittedTransaction(1, (session, i) -> {
            final RealmModel realm = session.realms().getRealm(realmId);
            final RoleModel role = session.roles().getRealmRole(realm, "realm-role");
            session.roles().removeRole(role);
            return null;
        });

        // check it is removed
        inComittedTransaction(1, (session, i) -> {
            final RealmModel realm = session.realms().getRealm(realmId);
            final ClientModel client1 = session.clients().getClientByClientId(realm, "client1");
            assertThat(client1.getScopeMappingsStream().count(), is(1L));
            assertThat(client1.getScopeMappingsStream().filter(r -> r.getName().equals("client2-role")).count(), is(1L));
            return null;
        });

        // remove client role
        inComittedTransaction(1, (session, i) -> {
            final RealmModel realm = session.realms().getRealm(realmId);
            final ClientModel client2 = session.clients().getClientByClientId(realm, "client2");
            final RoleModel role = session.roles().getClientRole(client2, "client2-role");
            session.roles().removeRole(role);
            return null;
        });

        // check both clients are removed
        inComittedTransaction(1, (session, i) -> {
            final RealmModel realm = session.realms().getRealm(realmId);
            final ClientModel client1 = session.clients().getClientByClientId(realm, "client1");
            assertThat(client1.getScopeMappingsStream().count(), is(0L));
            return null;
        });

        // remove clients
        inComittedTransaction(1, (session , i) -> {
            final RealmModel realm = session.realms().getRealm(realmId);
            final ClientModel client1 = session.clients().getClientByClientId(realm, "client1");
            final ClientModel client2 = session.clients().getClientByClientId(realm, "client2");
            session.clients().removeClient(realm, client1.getId());
            session.clients().removeClient(realm, client2.getId());
            return null;
        });
    }
}
