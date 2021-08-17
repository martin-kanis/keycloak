package org.keycloak.models.map.common;

import org.infinispan.query.dsl.Query;

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
}
