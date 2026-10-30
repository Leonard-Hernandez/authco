package authco.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrisTest {

    @Test
    @DisplayName("one trailing slash is stripped, nothing else")
    void stripTrailingSlash() {
        assertEquals("https://a.test/x", Uris.stripTrailingSlash("https://a.test/x/"));
        assertEquals("https://a.test/x", Uris.stripTrailingSlash("https://a.test/x"));
        assertEquals("", Uris.stripTrailingSlash("/"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "127.0.0.1", "[::1]", "localhost", "LocalHost" })
    @DisplayName("RFC 8252 loopback hosts are loopback, and local development hosts too")
    void loopback(String host) {
        assertTrue(Uris.isLoopbackHost(host));
        assertTrue(Uris.isLocalDevelopmentHost(host));
    }

    @ParameterizedTest
    @ValueSource(strings = { "finco.localhost", "API.Finco.localhost" })
    @DisplayName("*.localhost is a local development host (admin API) but not loopback (DCR)")
    void localhostDomain(String host) {
        assertFalse(Uris.isLoopbackHost(host));
        assertTrue(Uris.isLocalDevelopmentHost(host));
    }

    @ParameterizedTest
    @ValueSource(strings = { "127.0.0.2", "localhost.evil.com", "evil-localhost", "example.com", "::1" })
    @DisplayName("anything else is neither")
    void notLocal(String host) {
        assertFalse(Uris.isLoopbackHost(host));
        assertFalse(Uris.isLocalDevelopmentHost(host));
    }

    @Test
    @DisplayName("a missing host is not local")
    void nullHost() {
        assertFalse(Uris.isLoopbackHost(null));
        assertFalse(Uris.isLocalDevelopmentHost(null));
    }

}
