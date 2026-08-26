package org.keycloak.tests.broker;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.saml.SamlConfigAttributes;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.UserAttributeStatementMapper;
import org.keycloak.protocol.saml.mappers.UserPropertyAttributeStatementMapper;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.IdentityProviderBuilder;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;

import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.ARTIFACT_BINDING_RESPONSE;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.ARTIFACT_RESOLUTION_SERVICE_URL;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.BACKCHANNEL_SUPPORTED;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.FORCE_AUTHN;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.NAME_ID_POLICY_FORMAT;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.POST_BINDING_AUTHN_REQUEST;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.POST_BINDING_RESPONSE;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.SINGLE_LOGOUT_SERVICE_URL;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.SINGLE_SIGN_ON_SERVICE_URL;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.VALIDATE_SIGNATURE;
import static org.keycloak.broker.saml.SAMLIdentityProviderConfig.WANT_AUTHN_REQUESTS_SIGNED;
import static org.keycloak.protocol.saml.SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE;

public final class SamlBrokerRealmConfigs {

    static final String IDP_SAML_ALIAS = "kc-saml-idp";
    static final String IDP_SAML_PROVIDER_ID = "saml";
    static final String ATTRIBUTE_TO_MAP_NAME = "user-attribute";
    static final String ATTRIBUTE_TO_MAP_NAME_2 = "user-attribute-2";
    static final String ATTRIBUTE_TO_MAP_FRIENDLY_NAME = "user-attribute-friendly";

    // Placeholders used during realm creation; rewritten to actual URLs in configureBrokerEndpoints()
    private static final String PLACEHOLDER_BASE = "http://localhost:8080";
    private static final String PLACEHOLDER_CONSUMER_ENTITY_ID = PLACEHOLDER_BASE + "/realms/" + AbstractBrokerTest.CONSUMER_REALM;
    private static final String PLACEHOLDER_PROVIDER_SAML_ENDPOINT = PLACEHOLDER_BASE + "/realms/" + AbstractBrokerTest.PROVIDER_REALM + "/protocol/saml";
    private static final String PLACEHOLDER_CONSUMER_BROKER_ENDPOINT = PLACEHOLDER_CONSUMER_ENTITY_ID + "/broker/" + IDP_SAML_ALIAS + "/endpoint";

    private SamlBrokerRealmConfigs() {
    }

    static void configureBrokerEndpoints(ManagedRealm consumerRealm, ManagedRealm providerRealm) {
        String providerSamlEndpoint = providerRealm.getBaseUrl() + "/protocol/saml";
        String consumerBaseUrl = consumerRealm.getBaseUrl();
        String consumerBrokerEndpoint = consumerBaseUrl + "/broker/" + IDP_SAML_ALIAS + "/endpoint";

        // Consumer IdP -> provider SAML endpoint
        IdentityProviderResource idpResource = consumerRealm.admin().identityProviders().get(IDP_SAML_ALIAS);
        IdentityProviderRepresentation idp = idpResource.toRepresentation();
        Map<String, String> idpConfig = idp.getConfig();
        idpConfig.put(SINGLE_SIGN_ON_SERVICE_URL, providerSamlEndpoint);
        idpConfig.put(ARTIFACT_RESOLUTION_SERVICE_URL, providerSamlEndpoint);
        idpConfig.put(SINGLE_LOGOUT_SERVICE_URL, providerSamlEndpoint);
        idpResource.update(idp);

        // Provider SAML client -> consumer entity ID and endpoints
        ClientsResource providerClients = providerRealm.admin().clients();
        List<ClientRepresentation> found = providerClients.findByClientId(PLACEHOLDER_CONSUMER_ENTITY_ID);
        if (!found.isEmpty()) {
            ClientRepresentation client = found.get(0);
            client.setClientId(consumerBaseUrl);
            client.setRedirectUris(List.of(consumerBrokerEndpoint));
            Map<String, String> attributes = client.getAttributes();
            attributes.put(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE, consumerBrokerEndpoint);
            attributes.put(SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, consumerBrokerEndpoint);
            providerClients.get(client.getId()).update(client);
        }
    }

    static ProtocolMapperRepresentation createSamlProtocolMapper(String name, String protocolMapper,
            String userAttribute, String samlAttributeName, String nameFormat, String friendlyName) {
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName(name);
        mapper.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
        mapper.setProtocolMapper(protocolMapper);
        Map<String, String> config = mapper.getConfig();
        config.put(ProtocolMapperUtils.USER_ATTRIBUTE, userAttribute);
        config.put(AttributeStatementHelper.SAML_ATTRIBUTE_NAME, samlAttributeName);
        config.put(AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT, nameFormat);
        if (friendlyName != null) {
            config.put(AttributeStatementHelper.FRIENDLY_NAME, friendlyName);
        }
        return mapper;
    }

    public static class ProviderRealmConfig implements RealmConfig {
        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            Map<String, String> clientAttributes = new HashMap<>();
            clientAttributes.put(SamlConfigAttributes.SAML_AUTHNSTATEMENT, "true");
            clientAttributes.put(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE, PLACEHOLDER_CONSUMER_BROKER_ENDPOINT);
            clientAttributes.put(SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, PLACEHOLDER_CONSUMER_BROKER_ENDPOINT);
            clientAttributes.put(SamlConfigAttributes.SAML_FORCE_NAME_ID_FORMAT_ATTRIBUTE, "true");
            clientAttributes.put(SamlConfigAttributes.SAML_NAME_ID_FORMAT_ATTRIBUTE, "username");
            clientAttributes.put(SamlConfigAttributes.SAML_ASSERTION_SIGNATURE, "false");
            clientAttributes.put(SamlConfigAttributes.SAML_SERVER_SIGNATURE, "false");
            clientAttributes.put(SamlConfigAttributes.SAML_CLIENT_SIGNATURE_ATTRIBUTE, "false");
            clientAttributes.put(SamlConfigAttributes.SAML_ENCRYPT, "false");

            ClientBuilder samlClient = ClientBuilder.create(PLACEHOLDER_CONSUMER_ENTITY_ID)
                    .enabled(true)
                    .protocol(IDP_SAML_PROVIDER_ID)
                    .redirectUris(PLACEHOLDER_CONSUMER_BROKER_ENDPOINT)
                    .protocolMappers(
                            createSamlProtocolMapper("email", UserPropertyAttributeStatementMapper.PROVIDER_ID,
                                    "email", "urn:oid:1.2.840.113549.1.9.1",
                                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "email"),
                            createSamlProtocolMapper("email - dotted", UserAttributeStatementMapper.PROVIDER_ID,
                                    "dotted.email", "dotted.email",
                                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", null),
                            createSamlProtocolMapper("email - nested", UserAttributeStatementMapper.PROVIDER_ID,
                                    "nested.email", "nested.email",
                                    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", null),
                            createSamlProtocolMapper("attribute - name", UserAttributeStatementMapper.PROVIDER_ID,
                                    ATTRIBUTE_TO_MAP_NAME, ATTRIBUTE_TO_MAP_NAME,
                                    AttributeStatementHelper.BASIC, ""),
                            createSamlProtocolMapper("attribute - name 2", UserAttributeStatementMapper.PROVIDER_ID,
                                    ATTRIBUTE_TO_MAP_NAME_2, ATTRIBUTE_TO_MAP_NAME_2,
                                    AttributeStatementHelper.BASIC, ""),
                            createSamlProtocolMapper("attribute - friendly name", UserAttributeStatementMapper.PROVIDER_ID,
                                    ATTRIBUTE_TO_MAP_FRIENDLY_NAME, "urn:oid:1.2.3.4.5.6.7",
                                    AttributeStatementHelper.BASIC, ATTRIBUTE_TO_MAP_FRIENDLY_NAME));

            for (Map.Entry<String, String> attr : clientAttributes.entrySet()) {
                samlClient.attribute(attr.getKey(), attr.getValue());
            }

            return realm.name(AbstractBrokerTest.PROVIDER_REALM)
                    .eventsListeners("jboss-logging")
                    .users(UserBuilder.create(AbstractBrokerTest.USER_LOGIN)
                            .email(AbstractBrokerTest.USER_EMAIL)
                            .emailVerified(true)
                            .password(AbstractBrokerTest.USER_PASSWORD)
                            .enabled(true))
                    .clients(samlClient);
        }
    }

    public static class ConsumerRealmConfig implements RealmConfig {
        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            IdentityProviderBuilder idpBuilder = IdentityProviderBuilder.create()
                    .providerId(IDP_SAML_PROVIDER_ID)
                    .alias(IDP_SAML_ALIAS)
                    .attribute(IdentityProviderModel.SYNC_MODE, "IMPORT")
                    .attribute(SINGLE_SIGN_ON_SERVICE_URL, PLACEHOLDER_PROVIDER_SAML_ENDPOINT)
                    .attribute(ARTIFACT_RESOLUTION_SERVICE_URL, PLACEHOLDER_PROVIDER_SAML_ENDPOINT)
                    .attribute(SINGLE_LOGOUT_SERVICE_URL, PLACEHOLDER_PROVIDER_SAML_ENDPOINT)
                    .attribute(NAME_ID_POLICY_FORMAT, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                    .attribute(FORCE_AUTHN, "false")
                    .attribute(POST_BINDING_RESPONSE, "true")
                    .attribute(POST_BINDING_AUTHN_REQUEST, "true")
                    .attribute(VALIDATE_SIGNATURE, "false")
                    .attribute(WANT_AUTHN_REQUESTS_SIGNED, "false")
                    .attribute(BACKCHANNEL_SUPPORTED, "false")
                    .attribute(ARTIFACT_BINDING_RESPONSE, "false")
                    .trustEmail(true)
                    .storeToken(true);

            return realm.name(AbstractBrokerTest.CONSUMER_REALM)
                    .eventsListeners("jboss-logging")
                    .resetPasswordAllowed(true)
                    .identityProviders(idpBuilder.build())
                    .clients(ClientBuilder.create(AbstractBrokerTest.CONSUMER_BROKER_APP_CLIENT_ID)
                            .name(AbstractBrokerTest.CONSUMER_BROKER_APP_CLIENT_ID)
                            .secret(AbstractBrokerTest.CONSUMER_BROKER_APP_SECRET)
                            .directAccessGrantsEnabled()
                            .redirectUris("*"));
        }
    }
}