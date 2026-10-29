package authco.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.ObjectMapper;

import authco.config.TestContainerConfig;

/**
 * Anonymous Dynamic Client Registration as a remote MCP client (Claude.ai) does it,
 * on both the OIDC and the RFC 7591 endpoints, plus what the discovery documents
 * advertise.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class DynamicClientRegistrationIntegrationTest {

    private static final String CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static Map<String, Object> claudePublicClient() {
        return Map.of(
                "client_name", "Claude",
                "redirect_uris", List.of(CLAUDE_CALLBACK),
                "grant_types", List.of("authorization_code", "refresh_token"),
                "response_types", List.of("code"),
                "token_endpoint_auth_method", "none");
    }

    private MvcResult register(String endpoint, Map<String, Object> request) throws Exception {
        return mockMvc.perform(post(endpoint)
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(request)))
                .andReturn();
    }

    private Map<?, ?> body(MvcResult result) throws Exception {
        return JSON.readValue(result.getResponse().getContentAsString(), Map.class);
    }

    @ParameterizedTest
    @ValueSource(strings = { "/connect/register", "/oauth2/register" })
    @DisplayName("a Claude.ai-style public client registers without a secret and must use PKCE")
    void publicClientRegisters(String endpoint) throws Exception {
        MvcResult result = register(endpoint, claudePublicClient());

        assertEquals(201, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        Map<?, ?> response = body(result);
        assertEquals("none", response.get("token_endpoint_auth_method"));
        assertNull(response.get("client_secret"));

        RegisteredClient client = registeredClientRepository.findByClientId((String) response.get("client_id"));
        assertNotNull(client);
        assertNull(client.getClientSecret());
        assertEquals(Set.of(ClientAuthenticationMethod.NONE), client.getClientAuthenticationMethods());
        assertEquals(Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN),
                client.getAuthorizationGrantTypes());
        assertEquals(Set.of(CLAUDE_CALLBACK), client.getRedirectUris());
        assertTrue(client.getClientSettings().isRequireProofKey());
    }

    @ParameterizedTest
    @ValueSource(strings = { "/connect/register", "/oauth2/register" })
    @DisplayName("a confidential client gets its secret once, stored only as a hash")
    void confidentialClientSecretIsHashed(String endpoint) throws Exception {
        MvcResult result = register(endpoint, Map.of(
                "client_name", "Confidential",
                "redirect_uris", List.of(CLAUDE_CALLBACK),
                "grant_types", List.of("authorization_code"),
                "token_endpoint_auth_method", "client_secret_basic"));

        assertEquals(201, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        Map<?, ?> response = body(result);
        String plainSecret = (String) response.get("client_secret");
        assertNotNull(plainSecret);

        RegisteredClient client = registeredClientRepository.findByClientId((String) response.get("client_id"));
        assertTrue(client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
        assertTrue(passwordEncoder.matches(plainSecret, client.getClientSecret()));
    }

    @ParameterizedTest
    @ValueSource(strings = { "/connect/register", "/oauth2/register" })
    @DisplayName("a redirect URI outside the allowlist is rejected with invalid_redirect_uri")
    void unknownRedirectUriRejected(String endpoint) throws Exception {
        mockMvc.perform(post(endpoint)
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of(
                        "redirect_uris", List.of("https://evil.example.com/callback"),
                        "grant_types", List.of("authorization_code"),
                        "token_endpoint_auth_method", "none"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_redirect_uri"));
    }

    @Test
    @DisplayName("a loopback redirect URI is accepted on any port (RFC 8252)")
    void loopbackAnyPortAccepted() throws Exception {
        MvcResult result = register("/oauth2/register", Map.of(
                "redirect_uris", List.of("http://127.0.0.1:53682/callback"),
                "grant_types", List.of("authorization_code"),
                "token_endpoint_auth_method", "none"));

        assertEquals(201, result.getResponse().getStatus(), result.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("anonymous registration cannot ask for client_credentials")
    void clientCredentialsRejected() throws Exception {
        mockMvc.perform(post("/oauth2/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of(
                        "redirect_uris", List.of(CLAUDE_CALLBACK),
                        "grant_types", List.of("client_credentials"),
                        "token_endpoint_auth_method", "client_secret_basic"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client_metadata"));
    }

    @Test
    @DisplayName("both discovery documents advertise a registration endpoint under the pinned issuer")
    void discoveryAdvertisesRegistration() throws Exception {
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:8087/authco"))
                .andExpect(jsonPath("$.registration_endpoint").value("http://localhost:8087/authco/oauth2/register"));

        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:8087/authco"))
                .andExpect(jsonPath("$.registration_endpoint").value("http://localhost:8087/authco/connect/register"));
    }

    @Test
    @DisplayName("health probes answer without authentication and without details")
    void healthProbesArePublic() throws Exception {
        for (String path : List.of("/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness")) {
            mockMvc.perform(get(path))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("UP"))
                    .andExpect(jsonPath("$.components").doesNotExist());
        }
    }

    @Test
    @DisplayName("other actuator endpoints are not exposed")
    void otherActuatorEndpointsHidden() throws Exception {
        int status = mockMvc.perform(get("/actuator/env")).andReturn().getResponse().getStatus();
        assertTrue(status == 404 || status == 302 || status == 401, "unexpected status " + status);
    }

    @Test
    @DisplayName("the demo client is not seeded unless authco.seed-demo-client=true")
    void demoClientNotSeeded() {
        assertNull(registeredClientRepository.findByClientId("oidc-client"));
    }

}
