package org.keycloak.testsuite.model;

import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.exception.LiquibaseException;
import liquibase.structure.core.Schema;
import org.junit.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.connections.jpa.JpaConnectionProviderFactory;
import org.keycloak.connections.jpa.updater.liquibase.conn.LiquibaseConnectionProvider;
import org.keycloak.models.KeycloakSession;

import java.sql.Connection;

public class DBSchemaTest extends AbstractModelTest {


    /**
     * Run MySQL from docker and change /home/mkanis/.m2/repository/org/keycloak/keycloak-testsuite-utils/4.1.0.Final-SNAPSHOT/keycloak-testsuite-utils-4.1.0.Final-SNAPSHOT.jar!/META-INF/keycloak-server.json
     * "url": "${keycloak.connectionsJpa.url:jdbc:mysql://172.17.0.2/tmp-tmp}",
     * "driver": "${keycloak.connectionsJpa.driver:com.mysql.jdbc.Driver}",
     * "user": "${keycloak.connectionsJpa.user:keycloak}",
     * "password": "${keycloak.connectionsJpa.password:keycloak}",
     * "schema": "tmp-tmp"
     */
    @Test
    public void schemaNameTest() throws LiquibaseException {
        KeycloakSession session = realmManager.getSession();

        LiquibaseConnectionProvider liquibaseProvider = session.getProvider(LiquibaseConnectionProvider.class);
        JpaConnectionProviderFactory jpaProviderFactory = (JpaConnectionProviderFactory) session.getKeycloakSessionFactory().getProviderFactory(JpaConnectionProvider.class);

        Connection connection = jpaProviderFactory.getConnection();
        String defaultSchema = jpaProviderFactory.getSchema();
        Liquibase liquibase = liquibaseProvider.getLiquibase(connection, defaultSchema);
        Database database = liquibase.getDatabase();

        String schema = database.escapeObjectName(database.getDefaultSchemaName(), Schema.class);
        System.out.println(schema);
    }
}
