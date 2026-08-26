package org.keycloak.tests.broker;

import java.util.Map;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AudienceProtocolMapper;
import org.keycloak.protocol.oidc.mappers.HardcodedClaim;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.UserAttributeMapper;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.IdentityProviderBuilder;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.ProtocolMapperBuilder;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;

import static org.keycloak.broker.oidc.OAuth2IdentityProviderConfig.TOKEN_ENDPOINT_URL;

public final class KcOidcBrokerRealmConfigs {

    static final String IDP_OIDC_ALIAS = "kc-oidc-idp";
    static final String IDP_OIDC_PROVIDER_ID = KeycloakOIDCIdentityProviderFactory.PROVIDER_ID;
    static final String CLIENT_ID = "brokerapp";
    static final String CLIENT_SECRET = "secret";
    static final String ATTRIBUTE_TO_MAP_NAME = "user-attribute";
    static final String ATTRIBUTE_TO_MAP_NAME_2 = "user-attribute-2";

    private KcOidcBrokerRealmConfigs() {
    }

    static void configureBrokerEndpoints(ManagedRealm consumerRealm, ManagedRealm providerRealm, String idpAlias) {
        String providerBaseUrl = providerRealm.getBaseUrl();
        IdentityProviderRepresentation idp = consumerRealm.admin()
                .identityProviders().get(idpAlias).toRepresentation();
        Map<String, String> config = idp.getConfig();
        config.put(OIDCIdentityProviderConfig.ISSUER, providerBaseUrl);
        config.put("authorizationUrl", providerBaseUrl + "/protocol/openid-connect/auth");
        config.put(TOKEN_ENDPOINT_URL, providerBaseUrl + "/protocol/openid-connect/token");
        config.put("logoutUrl", providerBaseUrl + "/protocol/openid-connect/logout");
        config.put("userInfoUrl", providerBaseUrl + "/protocol/openid-connect/userinfo");
        config.put(OIDCIdentityProviderConfig.JWKS_URL, providerBaseUrl + "/protocol/openid-connect/certs");
        config.put(OIDCIdentityProviderConfig.USE_JWKS_URL, "true");
        config.put(OIDCIdentityProviderConfig.VALIDATE_SIGNATURE, "true");
        consumerRealm.admin().identityProviders().get(idpAlias).update(idp);
    }

    static IdentityProviderBuilder createOidcIdentityProvider() {
        return IdentityProviderBuilder.create()
                .providerId(IDP_OIDC_PROVIDER_ID)
                .alias(IDP_OIDC_ALIAS)
                .displayName("kc-oidc-idp")
                .attribute(IdentityProviderModel.SYNC_MODE, "IMPORT")
                .attribute("clientId", CLIENT_ID)
                .attribute("clientSecret", CLIENT_SECRET)
                .attribute("prompt", "login")
                .attribute("loginHint", "true")
                .attribute("backchannelSupported", "true")
                .attribute("defaultScope", "email profile");
    }

    static RealmBuilder configureConsumerRealm(RealmBuilder realm, IdentityProviderBuilder idpBuilder) {
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

    public static class ProviderRealmConfig implements RealmConfig {
        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return realm.name(AbstractBrokerTest.PROVIDER_REALM)
                    .eventsListeners("jboss-logging")
                    .users(UserBuilder.create(AbstractBrokerTest.USER_LOGIN)
                            .email(AbstractBrokerTest.USER_EMAIL)
                            .emailVerified(true)
                            .password(AbstractBrokerTest.USER_PASSWORD)
                            .enabled(true))
                    .clients(ClientBuilder.create(CLIENT_ID)
                            .secret(CLIENT_SECRET)
                            .redirectUris("*")
                            .protocolMappers(
                                    ProtocolMapperBuilder.create().name("email")
                                            .protocolMapper(UserAttributeMapper.PROVIDER_ID)
                                            .protocol(OIDCLoginProtocol.LOGIN_PROTOCOL)
                                            .config(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "email")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true")
                                            .config(OIDCAttributeMapperHelper.JSON_TYPE, "String")
                                            .config("user.attribute", "email")
                                            .build(),
                                    ProtocolMapperBuilder.create().name("nested.email")
                                            .protocolMapper(UserAttributeMapper.PROVIDER_ID)
                                            .protocol(OIDCLoginProtocol.LOGIN_PROTOCOL)
                                            .config(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "nested.email")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true")
                                            .config(OIDCAttributeMapperHelper.JSON_TYPE, "String")
                                            .config("user.attribute", "nested.email")
                                            .build(),
                                    ProtocolMapperBuilder.create().name("dotted.email")
                                            .protocolMapper(UserAttributeMapper.PROVIDER_ID)
                                            .protocol(OIDCLoginProtocol.LOGIN_PROTOCOL)
                                            .config(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "dotted\\.email")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true")
                                            .config(OIDCAttributeMapperHelper.JSON_TYPE, "String")
                                            .config("user.attribute", "dotted.email")
                                            .build(),
                                    ProtocolMapperBuilder.create().name(ATTRIBUTE_TO_MAP_NAME)
                                            .protocolMapper(UserAttributeMapper.PROVIDER_ID)
                                            .protocol(OIDCLoginProtocol.LOGIN_PROTOCOL)
                                            .config(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, ATTRIBUTE_TO_MAP_NAME)
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true")
                                            .config(OIDCAttributeMapperHelper.JSON_TYPE, "String")
                                            .config("user.attribute", ATTRIBUTE_TO_MAP_NAME)
                                            .build(),
                                    ProtocolMapperBuilder.create().name(ATTRIBUTE_TO_MAP_NAME_2)
                                            .protocolMapper(UserAttributeMapper.PROVIDER_ID)
                                            .protocol(OIDCLoginProtocol.LOGIN_PROTOCOL)
                                            .config(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, ATTRIBUTE_TO_MAP_NAME_2)
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true")
                                            .config(OIDCAttributeMapperHelper.JSON_TYPE, "String")
                                            .config("user.attribute", ATTRIBUTE_TO_MAP_NAME_2)
                                            .build(),
                                    ProtocolMapperBuilder.create().name("hardcoded-attribute")
                                            .protocolMapper(HardcodedClaim.PROVIDER_ID)
                                            .protocol(OIDCLoginProtocol.LOGIN_PROTOCOL)
                                            .config(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "hardcoded-attribute")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true")
                                            .config(OIDCAttributeMapperHelper.JSON_TYPE, "String")
                                            .config("claim.value", "hardcoded-value")
                                            .build(),
                                    ProtocolMapperBuilder.create().name("audience")
                                            .protocolMapper(AudienceProtocolMapper.PROVIDER_ID)
                                            .protocol(OIDCLoginProtocol.LOGIN_PROTOCOL)
                                            .config("included.custom.audience", CLIENT_ID)
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true")
                                            .config(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true")
                                            .build()));
        }
    }

    public static class ConsumerRealmConfig implements RealmConfig {
        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return configureConsumerRealm(realm, createOidcIdentityProvider());
        }
    }
}