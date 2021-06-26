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
package org.keycloak.models.map.connections;

import org.infinispan.client.hotrod.RemoteCacheManager;
import org.infinispan.client.hotrod.configuration.ClientIntelligence;
import org.infinispan.client.hotrod.configuration.ConfigurationBuilder;
import org.infinispan.commons.marshall.ProtoStreamMarshaller;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * @author <a href="mailto:mkanis@redhat.com">Martin Kanis</a>
 */
public class DefaultHotRodConnectionProviderFactory implements HotRodConnectionProviderFactory {

    public static final String PROVIDER_ID = "default";

    private RemoteCacheManager remoteCacheManager;

    @Override
    public HotRodConnectionProvider create(KeycloakSession session) {
        return new DefaultHotRodConnectionProvider(remoteCacheManager);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        ConfigurationBuilder remoteBuilder = new ConfigurationBuilder();
        remoteBuilder.addServer()
                .host("localhost")
                .port(11222)
                //.security().authentication().enable().saslMechanism("SCRAM-SHA-512").username("admin").password("password")
                .clientIntelligence(ClientIntelligence.BASIC) // TODO shouldn't use BASIC in production
                .marshaller(new ProtoStreamMarshaller());

        remoteCacheManager = new RemoteCacheManager(remoteBuilder.build());
    }
}
