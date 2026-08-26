package org.keycloak.tests.broker;

import java.util.List;
import java.util.Set;

import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.annotations.InjectWebDriver;
import org.keycloak.testframework.ui.page.IdpReviewUserProfilePage;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.keycloak.testsuite.util.AccountHelper;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.openqa.selenium.TimeoutException;

public abstract class AbstractBrokerTest {

    static final String PROVIDER_REALM = "provider";
    static final String CONSUMER_REALM = "consumer";
    static final String USER_LOGIN = "testuser";
    static final String USER_EMAIL = "user@localhost.com";
    static final String USER_PASSWORD = "password";
    static final String CONSUMER_BROKER_APP_CLIENT_ID = "broker-app";
    static final String CONSUMER_BROKER_APP_SECRET = "broker-app-secret";

    @InjectOAuthClient(realmRef = "consumer")
    protected OAuthClient oauth;

    @InjectWebDriver
    protected ManagedWebDriver webDriver;

    @InjectPage
    protected LoginPage loginPage;

    @InjectPage
    protected IdpReviewUserProfilePage updateProfilePage;

    protected abstract ManagedRealm getProviderRealm();

    protected abstract ManagedRealm getConsumerRealm();

    protected abstract String getIdpAlias();

    @BeforeEach
    void relaxProviderProfileVerification() {
        for (RequiredActionProviderRepresentation action : getProviderRealm().admin().flows().getRequiredActions()) {
            if (UserModel.RequiredAction.VERIFY_PROFILE.name().equals(action.getAlias())) {
                action.setEnabled(false);
                getProviderRealm().admin().flows().updateRequiredAction(action.getAlias(), action);
            }
        }
    }

    protected String getUserLogin() {
        return USER_LOGIN;
    }

    protected String getUserPassword() {
        return USER_PASSWORD;
    }

    protected String getUserEmail() {
        return USER_EMAIL;
    }

    protected void logInWithBroker() {
        loginPage.clickSocial(getIdpAlias());
    }

    protected void logInAsUserInIDP() {
        oauth.openLoginForm();
        logInWithBroker();
        logInAsUserInIDPForFirstTime();
    }

    protected void logInAsUserInIDPForFirstTime() {
        loginPage.fillLogin(getUserLogin(), getUserPassword());
        loginPage.submit();
    }

    protected void updateAccountInformation() {
        Assertions.assertTrue(profilePageAppeared(),
                "The first-broker-login review-profile page was expected but did not appear");
        updateProfilePage.update("Firstname", "Lastname");
    }

    protected void updateAccountInformationIfPresent() {
        if (profilePageAppeared()) {
            updateProfilePage.update("Firstname", "Lastname");
        }
    }

    private boolean profilePageAppeared() {
        Set<String> profilePageIds = Set.of("login-login-update-profile", "login-idp-review-user-profile");
        try {
            webDriver.waiting().until(d -> {
                String currentPageId = webDriver.page().getCurrentPageId();
                if (currentPageId != null && profilePageIds.contains(currentPageId)) {
                    return true;
                }
                return null;
            });
            return true;
        } catch (TimeoutException e) {
            return false;
        }
    }

    protected UserRepresentation createUser(String username, String email) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setEmailVerified(true);
        user.setEnabled(true);
        getConsumerRealm().admin().users().create(user).close();
        return user;
    }

    protected void logoutFromConsumerRealm() {
        AccountHelper.logout(getConsumerRealm().admin(), getUserLogin());
    }

    protected void assertNumFederatedIdentities(String username, int expected) {
        List<UserRepresentation> users = getConsumerRealm().admin().users().search(username, true);
        Assertions.assertEquals(1, users.size(), "Expected exactly one user with username " + username);
        List<FederatedIdentityRepresentation> fedIdentities =
                getConsumerRealm().admin().users().get(users.get(0).getId()).getFederatedIdentity();
        Assertions.assertEquals(expected, fedIdentities.size());
    }
}