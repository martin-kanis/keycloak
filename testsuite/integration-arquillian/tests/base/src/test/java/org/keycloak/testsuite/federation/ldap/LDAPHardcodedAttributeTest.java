/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.federation.ldap;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.storage.UserStoragePrivateUtil;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.HardcodedAttributeMapper;
import org.keycloak.storage.ldap.mappers.HardcodedAttributeMapperFactory;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.user.SynchronizationResult;
import org.keycloak.testsuite.runonserver.RunOnServerException;
import org.keycloak.testsuite.util.LDAPRule;
import org.keycloak.testsuite.util.LDAPTestUtils;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runners.MethodSorters;


@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LDAPHardcodedAttributeTest extends AbstractLDAPTest {

   @ClassRule
   public static LDAPRule ldapRule = new LDAPRule();

   @Rule
   public ExpectedException exceptionRule = ExpectedException.none();

   @Override
   protected LDAPRule getLDAPRule() {
      return ldapRule;
   }

   @Override
   protected void afterImportTestRealm() {
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();

         ComponentModel localeMapperModel = KeycloakModelUtils.createComponentModel("localeMapper", ctx.getLdapModel().getId(), HardcodedAttributeMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                HardcodedAttributeMapper.USER_MODEL_ATTRIBUTE, "locale",
                HardcodedAttributeMapper.ATTRIBUTE_VALUE, "en");
         ComponentModel emailVerifiedMapperModel = KeycloakModelUtils.createComponentModel("emailVerifiedMapper", ctx.getLdapModel().getId(), HardcodedAttributeMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                HardcodedAttributeMapper.USER_MODEL_ATTRIBUTE, "emailVerified",
                HardcodedAttributeMapper.ATTRIBUTE_VALUE, "true");

         appRealm.addComponentModel(localeMapperModel);
         appRealm.addComponentModel(emailVerifiedMapperModel);

          // Delete all LDAP users and add some new for testing
         LDAPStorageProvider ldapFedProvider = LDAPTestUtils.getLdapProvider(session, ctx.getLdapModel());
         LDAPTestUtils.removeAllLDAPUsers(ldapFedProvider, appRealm);

         LDAPTestUtils.addLDAPUser(ldapFedProvider, appRealm, "johnkeycloak", "John", "Doe",
               "john@email.org", null, "1234");

      });
   }


   @Test
   public void testHarcodedMapper(){
      testingClient.server().run(session -> {
            LDAPTestContext ctx = LDAPTestContext.init(session);
            RealmModel appRealm = ctx.getRealm();

            UserModel user = session.users().getUserByUsername(appRealm, "johnkeycloak");
            Assert.assertNotNull(user);
            Assert.assertTrue(user.isEmailVerified());
            Assert.assertEquals("en", user.getFirstAttribute("locale"));
        });
   }

   @Test
   public void testConfigInvalid(){
      exceptionRule.expect(RunOnServerException.class);
      exceptionRule.expectMessage("Attribute Name cannot be set to username or email");
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();

         ComponentModel usernameMapperModel = KeycloakModelUtils.createComponentModel("usernameMapper", ctx.getLdapModel().getId(), HardcodedAttributeMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                HardcodedAttributeMapper.USER_MODEL_ATTRIBUTE, "username",
                HardcodedAttributeMapper.ATTRIBUTE_VALUE, "username");
         appRealm.addComponentModel(usernameMapperModel);
      });
   }

   @Test
   public void testHardcodedMapperFullSyncExistingUsers(){
      // Step 1: Create users in LDAP without any hardcoded attribute mapper
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();
         LDAPStorageProvider ldapProvider = LDAPTestUtils.getLdapProvider(session, ctx.getLdapModel());

         // Remove all users and add test users
         LDAPTestUtils.removeAllLDAPUsers(ldapProvider, appRealm);
         LDAPTestUtils.addLDAPUser(ldapProvider, appRealm, "user1", "User1", "LastName1", "user1@email.org", null, "1111");
         LDAPTestUtils.addLDAPUser(ldapProvider, appRealm, "user2", "User2", "LastName2", "user2@email.org", null, "2222");
      });

      // Step 2: Sync users without hardcoded mapper - users should not have department attribute
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();

         SynchronizationResult syncResult = UserStoragePrivateUtil.runFullSync(sessionFactory, ctx.getLdapModel());
         Assert.assertTrue("Sync should succeed", syncResult.getFailed() == 0);
         Assert.assertEquals("Should sync 2 users", 2, syncResult.getAdded());
      });

      // Step 3: Verify users exist but don't have the department attribute yet
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();

         UserModel user1 = session.users().getUserByUsername(appRealm, "user1");
         UserModel user2 = session.users().getUserByUsername(appRealm, "user2");
         
         Assert.assertNotNull("User1 should exist", user1);
         Assert.assertNotNull("User2 should exist", user2);
         Assert.assertNull("User1 should not have department yet", user1.getFirstAttribute("department"));
         Assert.assertNull("User2 should not have department yet", user2.getFirstAttribute("department"));
      });

      // Step 4: Add hardcoded attribute mapper for department
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();

         ComponentModel departmentMapperModel = KeycloakModelUtils.createComponentModel("departmentMapper", 
                 ctx.getLdapModel().getId(), 
                 HardcodedAttributeMapperFactory.PROVIDER_ID, 
                 LDAPStorageMapper.class.getName(),
                 HardcodedAttributeMapper.USER_MODEL_ATTRIBUTE, "department",
                 HardcodedAttributeMapper.ATTRIBUTE_VALUE, "Engineering");
         
         appRealm.addComponentModel(departmentMapperModel);
      });

      // Step 5: Run full sync again - existing users should now get the hardcoded attribute
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();

         SynchronizationResult syncResult = UserStoragePrivateUtil.runFullSync(sessionFactory, ctx.getLdapModel());
         Assert.assertTrue("Second sync should succeed", syncResult.getFailed() == 0);
         Assert.assertEquals("Should update 2 existing users", 2, syncResult.getUpdated());
      });

      // Step 6: Verify existing users now have the hardcoded department attribute PERSISTED in database
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();

         // Use userLocalStorage to bypass LDAP proxy and read directly from database
         UserModel user1 = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(appRealm, "user1");
         UserModel user2 = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(appRealm, "user2");

         Assert.assertNotNull("User1 should still exist", user1);
         Assert.assertNotNull("User2 should still exist", user2);
         Assert.assertEquals("User1 should now have department persisted in DB", "Engineering", user1.getFirstAttribute("department"));
         Assert.assertEquals("User2 should now have department persisted in DB", "Engineering", user2.getFirstAttribute("department"));
      });

      // Step 7: Add a new user and sync - should also get the department attribute
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         LDAPStorageProvider ldapProvider = LDAPTestUtils.getLdapProvider(session, ctx.getLdapModel());

         LDAPTestUtils.addLDAPUser(ldapProvider, ctx.getRealm(), "user3", "User3", "LastName3", "user3@email.org", null, "3333");

         KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();

         SynchronizationResult syncResult = UserStoragePrivateUtil.runFullSync(sessionFactory, ctx.getLdapModel());
         Assert.assertTrue("Third sync should succeed", syncResult.getFailed() == 0);
         Assert.assertEquals("Should add 1 new user", 1, syncResult.getAdded());
      });

      // Step 8: Verify new user also gets the hardcoded attribute PERSISTED in database
      testingClient.server().run(session -> {
         LDAPTestContext ctx = LDAPTestContext.init(session);
         RealmModel appRealm = ctx.getRealm();

         // Use userLocalStorage to bypass LDAP proxy and read directly from database
         UserModel user3 = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(appRealm, "user3");
         Assert.assertNotNull("User3 should exist", user3);
         Assert.assertEquals("User3 should have department persisted in DB", "Engineering", user3.getFirstAttribute("department"));
      });
   }
}
