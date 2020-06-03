package org.keycloak.services.resources.admin;

import org.junit.Test;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JsonSerializerTest {
    private RoleRepresentation rep(int roleId) {
        RoleRepresentation res = new RoleRepresentation("role " + roleId, "description", true);
        return res;
    }

    @Test
    public void testStream() throws IOException {
        Random r = new Random();
        Stream<RoleRepresentation> s = Stream.generate(() -> rep(r.nextInt())).limit(1000000);

        JsonSerialization.prettyMapper.writeValue(System.out, s);
    }

    @Test
    public void testList() throws IOException {
        Random r = new Random();
        Stream<RoleRepresentation> s = Stream.generate(() -> rep(r.nextInt())).limit(1000000);
        List<RoleRepresentation> list = s.collect(Collectors.toList());

        JsonSerialization.prettyMapper.writeValue(System.out, list);
    }
}
