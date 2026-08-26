package org.keycloak.tests.broker;

import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.realm.ManagedRealm;

import org.junit.jupiter.api.BeforeEach;

@KeycloakIntegrationTest
public class KcSamlBrokerTest extends AbstractBrokerLoginTest {

    @InjectRealm(ref = "provider", lifecycle = LifeCycle.METHOD,
            config = SamlBrokerRealmConfigs.ProviderRealmConfig.class)
    ManagedRealm providerRealm;

    @InjectRealm(ref = "consumer", lifecycle = LifeCycle.METHOD,
            config = SamlBrokerRealmConfigs.ConsumerRealmConfig.class)
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
        return SamlBrokerRealmConfigs.IDP_SAML_ALIAS;
    }

    @BeforeEach
    void configureSamlBrokerEndpoints() {
        SamlBrokerRealmConfigs.configureBrokerEndpoints(consumerRealm, providerRealm);
    }
}