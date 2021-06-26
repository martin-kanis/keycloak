package org.keycloak.models.map.common;

import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.query.dsl.Query;
import org.infinispan.rest.RestServer;
import org.infinispan.rest.configuration.RestServerConfigurationBuilder;
import org.infinispan.server.configuration.endpoint.SinglePortServerConfigurationBuilder;
import org.infinispan.server.hotrod.HotRodServer;
import org.infinispan.server.hotrod.configuration.HotRodServerConfigurationBuilder;
import org.infinispan.server.router.RoutingTable;
import org.infinispan.server.router.configuration.SinglePortRouterConfiguration;
import org.infinispan.server.router.router.impl.singleport.SinglePortEndpointRouter;
import org.infinispan.server.router.routes.Route;
import org.infinispan.server.router.routes.RouteDestination;
import org.infinispan.server.router.routes.RouteSource;
import org.infinispan.server.router.routes.hotrod.HotRodServerRouteDestination;
import org.infinispan.server.router.routes.rest.RestServerRouteDestination;
import org.infinispan.server.router.routes.singleport.SinglePortRouteSource;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class HotRodUtils {
    public static <T> Query<T> paginateQuery(Query<T> query, Integer first, Integer max) {
        if (first != null && first > 0) {
            query = query.startOffset(first);
        }

        if (max != null && max >= 0) {
            query = query.maxResults(max);
        }

        return query;
    }

    /**
     * Not suitable for a production usage. Only for development and test purposes.
     * Also do not use in clustered environment.
     * @param hotRodServer HotRodServer
     * @param hotRodCacheManager DefaultCacheManager
     * @param embeddedPort int
     */
    public static void createHotRodMapStoreServer(HotRodServer hotRodServer, DefaultCacheManager hotRodCacheManager, int embeddedPort) {
        HotRodServerConfigurationBuilder hotRodServerConfigurationBuilder = new HotRodServerConfigurationBuilder();
        hotRodServerConfigurationBuilder.startTransport(false);
        hotRodServerConfigurationBuilder.port(embeddedPort);
        hotRodServer.start(hotRodServerConfigurationBuilder.build(), hotRodCacheManager);

        RestServerConfigurationBuilder restServerConfigurationBuilder = new RestServerConfigurationBuilder();
        restServerConfigurationBuilder.startTransport(false);
        restServerConfigurationBuilder.port(embeddedPort);
        RestServer restServer = new RestServer();
        restServer.start(restServerConfigurationBuilder.build(), hotRodCacheManager);

        SinglePortRouteSource routeSource = new SinglePortRouteSource();
        Set<Route<? extends RouteSource, ? extends RouteDestination>> routes = new HashSet<>();
        routes.add(new Route<>(routeSource, new HotRodServerRouteDestination("hotrod", hotRodServer)));
        routes.add(new Route<>(routeSource, new RestServerRouteDestination("rest", restServer)));

        SinglePortRouterConfiguration singlePortRouter = new SinglePortServerConfigurationBuilder().port(embeddedPort).build();
        SinglePortEndpointRouter endpointServer = new SinglePortEndpointRouter(singlePortRouter);
        endpointServer.start(new RoutingTable(routes));
    }

    /**
     * Not suitable for a production usage. Only for development and test purposes.
     * Also do not use in clustered environment.
     * @param embeddedPort int
     */
    public static void createHotRodMapStoreServer(int embeddedPort) {
        DefaultCacheManager hotRodCacheManager = null;
        try {
            hotRodCacheManager = new DefaultCacheManager("config/infinispan.xml");
        } catch (IOException e) {
            new RuntimeException("Cannot initialize cache manager!", e);
        }

        HotRodUtils.createHotRodMapStoreServer(new HotRodServer(), hotRodCacheManager, embeddedPort);
    }
}
