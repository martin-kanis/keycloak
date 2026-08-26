package org.keycloak.tests.broker;

import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;

import org.junit.jupiter.api.BeforeEach;

@KeycloakIntegrationTest
public class KcOidcBrokerClientSecretBasicAuthTest extends AbstractBrokerLoginTest {

    @InjectRealm(ref = "provider", lifecycle = LifeCycle.METHOD,
            config = KcOidcBrokerRealmConfigs.ProviderRealmConfig.class)
    ManagedRealm providerRealm;

    @InjectRealm(ref = "consumer", lifecycle = LifeCycle.METHOD,
            config = ConsumerRealmWithBasicAuth.class)
    ManagedRealm consumerRealm;

    @Override
    protected ManagedRealm getProviderRealm() {
        return providerRealm;
    }

    @Override
    protected ManagedRealm getConsumerRealm() {
        return consumerRealm;
    }

    @Override
    protected String getIdpAlias() {
        return KcOidcBrokerRealmConfigs.IDP_OIDC_ALIAS;
    }

    @BeforeEach
    void configureBrokerEndpoints() {
        KcOidcBrokerRealmConfigs.configureBrokerEndpoints(consumerRealm, providerRealm, getIdpAlias());
    }

    static class ConsumerRealmWithBasicAuth implements RealmConfig {
        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return KcOidcBrokerRealmConfigs.configureConsumerRealm(realm,
                    KcOidcBrokerRealmConfigs.createOidcIdentityProvider()
                            .attribute("clientAuthMethod", OIDCLoginProtocol.CLIENT_SECRET_BASIC));
        }
    }
}