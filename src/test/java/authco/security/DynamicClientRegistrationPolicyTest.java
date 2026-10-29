package authco.security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

class DynamicClientRegistrationPolicyTest {

    private final DynamicClientRegistrationPolicy policy = new DynamicClientRegistrationPolicy(List.of(
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            "http://127.0.0.1:*",
            "http://localhost:*/callback",
            // Not loopback (RFC 8252): the wildcard port is never honored for it.
            "http://finco.localhost:*"));

    @ParameterizedTest
    @ValueSource(strings = {
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            "http://127.0.0.1:8888/callback",
            "http://127.0.0.1:53682/",
            "http://127.0.0.1/anything",
            "http://localhost:4000/callback" })
    @DisplayName("allowlisted URIs and loopback on any port are accepted")
    void allowed(String redirectUri) {
        assertTrue(policy.isAllowed(redirectUri));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://claude.ai/api/mcp/auth_callback/extra",
            "https://claude.ai/api/mcp/auth_callback#frag",
            "https://evil.example.com/callback",
            "https://127.0.0.1:8888/callback",
            "http://127.0.0.1.evil.com:8888/callback",
            "http://user@127.0.0.1:8888/callback",
            "http://localhost:4000/other",
            "http://finco.localhost:4000/callback",
            "not a uri" })
    @DisplayName("anything else is rejected")
    void rejected(String redirectUri) {
        assertFalse(policy.isAllowed(redirectUri));
    }

    @Test
    @DisplayName("post-logout redirect URIs are optional but must be allowlisted")
    void postLogoutRedirectUris() {
        assertDoesNotThrow(() -> policy.validatePostLogoutRedirectUris(null));
        assertDoesNotThrow(() -> policy.validatePostLogoutRedirectUris(List.of()));
        assertDoesNotThrow(() -> policy.validatePostLogoutRedirectUris(List.of("http://127.0.0.1:8888/")));

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class,
                () -> policy.validatePostLogoutRedirectUris(List.of("https://evil.example.com/")));
        assertEquals("invalid_client_metadata", ex.getError().getErrorCode());
    }

}
