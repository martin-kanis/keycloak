package org.keycloak.testsuite.model;

import org.infinispan.client.hotrod.RemoteCacheManager;
import org.infinispan.commons.dataconversion.MediaType;
import org.infinispan.configuration.cache.BackupConfiguration;
import org.infinispan.configuration.cache.BackupFailurePolicy;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.Configuration;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.jboss.marshalling.commons.GenericJBossMarshaller;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.rest.configuration.RestServerConfigurationBuilder;
import org.infinispan.server.hotrod.HotRodServer;
import org.infinispan.server.hotrod.configuration.HotRodServerConfiguration;
import org.infinispan.server.hotrod.configuration.HotRodServerConfigurationBuilder;
import org.infinispan.server.router.RoutingTable;
import org.infinispan.server.router.configuration.SinglePortRouterConfiguration;
import org.infinispan.server.router.router.impl.singleport.SinglePortEndpointRouter;
import org.infinispan.server.router.routes.singleport.SinglePortRouteSource;
import org.infinispan.server.router.routes.Route;
import org.infinispan.server.router.routes.RouteSource;
import org.infinispan.server.router.routes.RouteDestination;
import org.infinispan.server.router.routes.hotrod.HotRodServerRouteDestination;
import org.infinispan.server.router.routes.rest.RestServerRouteDestination;
import org.infinispan.server.configuration.endpoint.SinglePortServerConfigurationBuilder;
import org.infinispan.rest.RestServer;
import org.junit.rules.ExternalResource;
import org.keycloak.Config;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static org.keycloak.connections.infinispan.InfinispanConnectionProvider.ACTION_TOKEN_CACHE;
import static org.keycloak.connections.infinispan.InfinispanConnectionProvider.CLIENT_SESSION_CACHE_NAME;
import static org.keycloak.connections.infinispan.InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME;
import static org.keycloak.connections.infinispan.InfinispanConnectionProvider.OFFLINE_CLIENT_SESSION_CACHE_NAME;
import static org.keycloak.connections.infinispan.InfinispanConnectionProvider.OFFLINE_USER_SESSION_CACHE_NAME;
import static org.keycloak.connections.infinispan.InfinispanConnectionProvider.USER_SESSION_CACHE_NAME;
import static org.keycloak.connections.infinispan.InfinispanConnectionProvider.WORK_CACHE_NAME;

public class HotRodServerRule extends ExternalResource {

    protected HotRodServer hotRodServer;

    protected HotRodServer hotRodServer2;

    protected RemoteCacheManager remoteCacheManager;

    protected DefaultCacheManager hotRodCacheManager;

    protected DefaultCacheManager hotRodCacheManager2;

    public void createEmbeddedHotRodServer(Config.Scope config) {
        try {
            hotRodCacheManager = new DefaultCacheManager("hotRod/hotRod1.xml");
            hotRodCacheManager2 = new DefaultCacheManager("hotRod/hotRod2.xml");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        HotRodServerConfiguration build = new HotRodServerConfigurationBuilder().build();
        hotRodServer = new HotRodServer();
        hotRodServer.start(build, hotRodCacheManager);

        HotRodServerConfiguration build2 = new HotRodServerConfigurationBuilder().port(11333).build();
        hotRodServer2 = new HotRodServer();
        hotRodServer2.start(build2, hotRodCacheManager2);

        // Create a Hot Rod client
        org.infinispan.client.hotrod.configuration.ConfigurationBuilder remoteBuilder = new org.infinispan.client.hotrod.configuration.ConfigurationBuilder();
        remoteBuilder.marshaller(new GenericJBossMarshaller());
        org.infinispan.client.hotrod.configuration.Configuration cfg = remoteBuilder
                .addServers(hotRodServer.getHost() + ":" + hotRodServer.getPort() + ";"
                        + hotRodServer2.getHost() + ":" + hotRodServer2.getPort()).build();
        remoteCacheManager = new RemoteCacheManager(cfg);

        boolean async = config.getBoolean("async", false);

        // create remote keycloak caches
        createKeycloakCaches(async, USER_SESSION_CACHE_NAME, OFFLINE_USER_SESSION_CACHE_NAME, CLIENT_SESSION_CACHE_NAME,
                OFFLINE_CLIENT_SESSION_CACHE_NAME, LOGIN_FAILURE_CACHE_NAME, WORK_CACHE_NAME, ACTION_TOKEN_CACHE);

        getCaches(USER_SESSION_CACHE_NAME, OFFLINE_USER_SESSION_CACHE_NAME, CLIENT_SESSION_CACHE_NAME, OFFLINE_CLIENT_SESSION_CACHE_NAME,
                LOGIN_FAILURE_CACHE_NAME, WORK_CACHE_NAME, ACTION_TOKEN_CACHE);
    }

    public void createHotRodMapStoreServer() {
        hotRodCacheManager = configureHotRodCacheManager("hotRod/infinispan.xml");

        HotRodServerConfigurationBuilder hotRodServerConfigurationBuilder = new HotRodServerConfigurationBuilder();
        hotRodServerConfigurationBuilder.startTransport(false);
        hotRodServer = new HotRodServer();
        hotRodServer.start(hotRodServerConfigurationBuilder.build(), hotRodCacheManager);

        RestServerConfigurationBuilder restServerConfigurationBuilder = new RestServerConfigurationBuilder();
        restServerConfigurationBuilder.startTransport(false);
        RestServer restServer = new RestServer();
        restServer.start(restServerConfigurationBuilder.build(), hotRodCacheManager);

        SinglePortRouteSource routeSource = new SinglePortRouteSource();
        Set<Route<? extends RouteSource, ? extends RouteDestination>> routes = new HashSet<>();
        routes.add(new Route<>(routeSource, new HotRodServerRouteDestination("hotrod", hotRodServer)));
        routes.add(new Route<>(routeSource, new RestServerRouteDestination("rest", restServer)));

        SinglePortRouterConfiguration singlePortRouter = new SinglePortServerConfigurationBuilder().build();
        SinglePortEndpointRouter endpointServer = new SinglePortEndpointRouter(singlePortRouter);
        endpointServer.start(new RoutingTable(routes));
    }

    private DefaultCacheManager configureHotRodCacheManager(String configPath) {
        DefaultCacheManager manager = null;
        try {
            manager = new DefaultCacheManager(configPath);
        } catch (IOException e) {
            new RuntimeException(e);
        }

        return manager;
    }

    private void getCaches(String ...cache) {
        for (String c: cache) {
            hotRodCacheManager.getCache(c, true);
            hotRodCacheManager2.getCache(c, true);
        }
    }

    private void createKeycloakCaches(boolean async, String ...cache) {
        ConfigurationBuilder sessionConfigBuilder1 = createCacheConfigurationBuilder();
        ConfigurationBuilder sessionConfigBuilder2 = createCacheConfigurationBuilder();
        sessionConfigBuilder1.clustering().cacheMode(async ? CacheMode.REPL_ASYNC: CacheMode.REPL_SYNC);
        sessionConfigBuilder2.clustering().cacheMode(async ? CacheMode.REPL_ASYNC: CacheMode.REPL_SYNC);

        sessionConfigBuilder1.sites().addBackup()
                .site("site-2").backupFailurePolicy(BackupFailurePolicy.IGNORE).strategy(BackupConfiguration.BackupStrategy.SYNC)
                .replicationTimeout(15000).enabled(true);
        sessionConfigBuilder2.sites().addBackup()
                .site("site-1").backupFailurePolicy(BackupFailurePolicy.IGNORE).strategy(BackupConfiguration.BackupStrategy.SYNC)
                .replicationTimeout(15000).enabled(true);

        Configuration sessionCacheConfiguration1 = sessionConfigBuilder1.build();
        Configuration sessionCacheConfiguration2 = sessionConfigBuilder2.build();
        for (String c: cache) {
            hotRodCacheManager.defineConfiguration(c, sessionCacheConfiguration1);
            hotRodCacheManager2.defineConfiguration(c, sessionCacheConfiguration2);
        }
    }

    public static ConfigurationBuilder createCacheConfigurationBuilder() {
        ConfigurationBuilder builder = new ConfigurationBuilder();

        // need to force the encoding to application/x-jboss-marshalling to avoid unnecessary conversion of keys/values. See WFLY-14356.
        builder.encoding().mediaType(MediaType.APPLICATION_JBOSS_MARSHALLING_TYPE);

        return builder;
    }

    public RemoteCacheManager getRemoteCacheManager() {
        return remoteCacheManager;
    }

    public HotRodServer getHotRodServer() {
        return hotRodServer;
    }

    public HotRodServer getHotRodServer2() {
        return hotRodServer2;
    }

    public DefaultCacheManager getHotRodCacheManager() {
        return hotRodCacheManager;
    }

    public DefaultCacheManager getHotRodCacheManager2() {
        return hotRodCacheManager2;
    }
}
