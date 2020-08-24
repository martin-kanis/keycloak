package org.keycloak.utils;

import org.hibernate.ScrollableResults;

import java.util.function.Function;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class StreamsUtil {
    public static <T> Stream<T> closing(Stream<T> stream) {
        return Stream.of(stream).flatMap(Function.identity());
    }

    public static <T> Stream<T> resultStream(Class<T> clazz, int batchSize, ScrollableResults results) {
        return resultStream(new ScrollableResultsSpliterator<T>(clazz, batchSize, results));
    }

    public static <T> Stream<T> resultStream(ScrollableResultsSpliterator<T> spliterator) {
        return StreamSupport.stream(spliterator, false)
                .onClose(spliterator::close);
    }
}

