package org.keycloak.utils;

import org.hibernate.ScrollableResults;

import java.util.function.Consumer;

public class ScrollableResultsSpliterator<T> extends FixedBatchSpliteratorBase<T> {
    private final ScrollableResults results;
    private boolean closed;
    private Boolean canUnwrap;

    public ScrollableResultsSpliterator(
            Class<T> clazz, int batchSize, ScrollableResults results)
    {
        super(ORDERED | NONNULL, batchSize);
        if (results == null)
            throw new NullPointerException("ScrollableResults must not be null");
        this.results = results;
    }

    @Override public boolean tryAdvance(Consumer<? super T> action) {
        if (closed) return false;
        if (!results.next()) {
            close();
            return false;
        }
        if (canUnwrap == null) {
            Object[] r = results.get();
            canUnwrap = r.length == 1;
            action.accept((T) (canUnwrap ? r[0] : r));
        } else {
            action.accept((T) (canUnwrap ? results.get(0) : results.get()));
        }
        return true;
    }

    public void close() {
        if (!closed) {
            results.close();
            closed = true;
        }
    }
}
