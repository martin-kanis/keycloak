package org.keycloak.tests.broker;

import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.util.AccountHelper;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public abstract class AbstractBrokerLoginTest extends AbstractBrokerTest {

    @Test
    void testLogInAsUserInIDP() {
        loginUser();
        verifyLogout();
    }

    protected void loginUser() {
        logInAsUserInIDP();

        updateAccountInformation();

        UserRepresentation userRep = AccountHelper.getUserRepresentation(
                getConsumerRealm().admin(), getUserLogin());
        Assertions.assertNotNull(userRep, "There must be user " + getUserLogin() + " in consumer realm");
        Assertions.assertEquals("Firstname", userRep.getFirstName(),
                "First name should have been persisted by the review-profile page");
        Assertions.assertEquals("Lastname", userRep.getLastName(),
                "Last name should have been persisted by the review-profile page");

        int userCount = getConsumerRealm().admin().users().count();
        Assertions.assertTrue(userCount > 0, "There must be at least one user");

        Assertions.assertEquals(getUserEmail(), userRep.getEmail(),
                "There must be user " + getUserLogin() + " with the expected email in consumer realm");
    }

    protected void verifyLogout() {
        oauth.openLoginForm();
        Assertions.assertTrue(oauth.parseLoginResponse().isSuccess(), "Should be logged in");

        AccountHelper.logout(getConsumerRealm().admin(), getUserLogin());
        AccountHelper.logout(getProviderRealm().admin(), getUserLogin());

        oauth.openLoginForm();
        loginPage.assertCurrent();
    }

    @Test
    void testLoginWithExistingUser() {
        int userCountBefore = getConsumerRealm().admin().users().count();

        testLogInAsUserInIDP();

        int userCount = getConsumerRealm().admin().users().count();
        Assertions.assertEquals(userCountBefore + 1, userCount,
                "First broker login should have created exactly one user in the consumer realm");

        oauth.openLoginForm();

        logInWithBroker();

        loginPage.fillLogin(getUserLogin(), getUserPassword());
        loginPage.submit();

        Assertions.assertTrue(oauth.parseLoginResponse().isSuccess());
        Assertions.assertEquals(userCount, getConsumerRealm().admin().users().count());
    }
}