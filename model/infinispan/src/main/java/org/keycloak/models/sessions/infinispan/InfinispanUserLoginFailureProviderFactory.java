package org.keycloak.models.sessions.infinispan;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.persistence.remote.RemoteStore;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.common.util.Time;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserLoginFailureProvider;
import org.keycloak.models.UserLoginFailureProviderFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.entities.LoginFailureEntity;
import org.keycloak.models.sessions.infinispan.entities.LoginFailureKey;
import org.keycloak.models.sessions.infinispan.entities.SessionEntity;
import org.keycloak.models.sessions.infinispan.events.AbstractUserSessionClusterListener;
import org.keycloak.models.sessions.infinispan.events.RemoveAllUserLoginFailuresEvent;
import org.keycloak.models.sessions.infinispan.remotestore.RemoteCacheInvoker;
import org.keycloak.models.sessions.infinispan.remotestore.RemoteCacheSessionListener;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;
import org.keycloak.models.sessions.infinispan.util.SessionTimeouts;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;

import java.util.Set;
import java.util.function.BiFunction;

public class InfinispanUserLoginFailureProviderFactory implements UserLoginFailureProviderFactory {

    private static final Logger log = Logger.getLogger(InfinispanUserSessionProviderFactory.class);

    public static final String PROVIDER_ID = "infinispan";

    public static final String REMOVE_ALL_LOGIN_FAILURES_EVENT = "REMOVE_ALL_LOGIN_FAILURES_EVENT";

    private Config.Scope config;

    private RemoteCacheInvoker remoteCacheInvoker;

    @Override
    public UserLoginFailureProvider create(KeycloakSession session) {
        InfinispanConnectionProvider connections = session.getProvider(InfinispanConnectionProvider.class);
        Cache<LoginFailureKey, SessionEntityWrapper<LoginFailureEntity>> loginFailures = connections.getCache(InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME);

        return new InfinispanUserLoginFailureProvider(session, remoteCacheInvoker, loginFailures);
    }

    @Override
    public void init(Config.Scope config) {
        this.config = config;
    }

    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        KeycloakModelUtils.runJobInTransaction(factory, (KeycloakSession session) -> {
            this.remoteCacheInvoker = new RemoteCacheInvoker();
        });

        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                KeycloakModelUtils.runJobInTransaction(factory, (KeycloakSession session) -> {
                    checkRemoteCaches(session);
                    registerClusterListeners(session);
                });
            }
        });
    }

    protected void registerClusterListeners(KeycloakSession session) {
        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        ClusterProvider cluster = session.getProvider(ClusterProvider.class);

        cluster.registerListener(REMOVE_ALL_LOGIN_FAILURES_EVENT,
                new AbstractUserSessionClusterListener<RemoveAllUserLoginFailuresEvent, UserLoginFailureProvider>(sessionFactory, UserLoginFailureProvider.class) {

            @Override
            protected void eventReceived(KeycloakSession session, UserLoginFailureProvider provider, RemoveAllUserLoginFailuresEvent sessionEvent) {
                provider.removeAllUserLoginFailures(sessionEvent.getRealmId());
            }

        });

        log.debug("Registered cluster listeners");
    }


    protected void checkRemoteCaches(KeycloakSession session) {
        InfinispanConnectionProvider ispn = session.getProvider(InfinispanConnectionProvider.class);

        Cache<LoginFailureKey, SessionEntityWrapper<LoginFailureEntity>> loginFailuresCache = ispn.getCache(InfinispanConnectionProvider.LOGIN_FAILURE_CACHE_NAME);
        checkRemoteCache(session, loginFailuresCache, (RealmModel realm) ->
                Time.toMillis(realm.getMaxDeltaTimeSeconds()), SessionTimeouts::getLoginFailuresLifespanMs, SessionTimeouts::getLoginFailuresMaxIdleMs);
    }

    private <K, V extends SessionEntity> RemoteCache checkRemoteCache(KeycloakSession session, Cache<K, SessionEntityWrapper<V>> ispnCache, RemoteCacheInvoker.MaxIdleTimeLoader maxIdleLoader,
                                                                      BiFunction<RealmModel, V, Long> lifespanMsLoader, BiFunction<RealmModel, V, Long> maxIdleTimeMsLoader) {
        Set<RemoteStore> remoteStores = InfinispanUtil.getRemoteStores(ispnCache);

        if (remoteStores.isEmpty()) {
            log.debugf("No remote store configured for cache '%s'", ispnCache.getName());
            return null;
        } else {
            log.infof("Remote store configured for cache '%s'", ispnCache.getName());

            RemoteCache<K, SessionEntityWrapper<V>> remoteCache = (RemoteCache) remoteStores.iterator().next().getRemoteCache();

            if (remoteCache == null) {
                throw new IllegalStateException("No remote cache available for the infinispan cache: " + ispnCache.getName());
            }

            remoteCacheInvoker.addRemoteCache(ispnCache.getName(), remoteCache, maxIdleLoader);

            RemoteCacheSessionListener hotrodListener = RemoteCacheSessionListener.createListener(session, ispnCache, remoteCache, lifespanMsLoader, maxIdleTimeMsLoader);
            remoteCache.addClientListener(hotrodListener);
            return remoteCache;
        }
    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
