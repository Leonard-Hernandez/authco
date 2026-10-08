package authco.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.fasterxml.jackson.databind.ObjectMapper;

import authco.admin.AdminCredentialRepository;
import authco.config.TestContainerConfig;

/**
 * Client registration through the admin API, checked against what Spring
 * Authorization Server actually loads from the database.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class ClientAdminIntegrationTest {

    private static final String ADMIN_PASSWORD = "integration-admin-password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private AdminCredentialRepository adminCredentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void knownAdminPassword() {
        adminCredentialRepository.findById("admin").ifPresent(admin -> {
            admin.setPasswordHash(passwordEncoder.encode(ADMIN_PASSWORD));
            adminCredentialRepository.save(admin);
        });
    }

    private RequestPostProcessor admin() {
        return httpBasic("admin", ADMIN_PASSWORD);
    }

    private static String uniqueClientId() {
        return "client-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private static String body(String clientId, String type, String redirectUri, String scopes, boolean consent) {
        return """
                {"clientId": "%s", "clientName": "Test App", "type": "%s",
                 "redirectUris": ["%s"], "postLogoutRedirectUris": ["http://localhost:4200/"],
                 "scopes": [%s], "requireConsent": %s}
                """.formatted(clientId, type, redirectUri, scopes, consent);
    }

    private String createPublic(String clientId) throws Exception {
        return mockMvc.perform(post("/admin/clients").with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(clientId, "PUBLIC", "http://localhost:4200/auth/callback",
                        "\"openid\", \"profile\", \"email\"", false)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
    }

    @Test
    @DisplayName("a public client is stored without secret, with PKCE and the requested consent policy")
    void createsPublicClient() throws Exception {
        String clientId = uniqueClientId();

        String response = createPublic(clientId);

        assertNull(objectMapper.readValue(response, Map.class).get("clientSecret"));
        RegisteredClient stored = registeredClientRepository.findByClientId(clientId);
        assertTrue(stored.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE));
        assertTrue(stored.getClientSettings().isRequireProofKey());
        assertFalse(stored.getClientSettings().isRequireAuthorizationConsent());
        assertFalse(stored.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN),
                "public clients never get refresh tokens, so the grant is not declared");
    }

    @Test
    @DisplayName("a confidential client gets a secret once; only its hash is stored")
    @SuppressWarnings("unchecked")
    void createsConfidentialClient() throws Exception {
        String clientId = uniqueClientId();

        String response = mockMvc.perform(post("/admin/clients").with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(clientId, "CONFIDENTIAL", "https://app.example.com/callback", "\"openid\"", true)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        String secret = (String) objectMapper.readValue(response, Map.class).get("clientSecret");
        RegisteredClient stored = registeredClientRepository.findByClientId(clientId);
        assertNotEquals(secret, stored.getClientSecret(), "the clear secret must never be stored");
        assertTrue(passwordEncoder.matches(secret, stored.getClientSecret()));
        assertTrue(stored.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));

        mockMvc.perform(get("/admin/clients/{id}", clientId).with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").doesNotExist())
                .andExpect(jsonPath("$.type").value("CONFIDENTIAL"));
    }

    @Test
    @DisplayName("a taken client_id is a 409")
    void duplicateClientIdIs409() throws Exception {
        String clientId = uniqueClientId();
        createPublic(clientId);

        mockMvc.perform(post("/admin/clients").with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(clientId, "PUBLIC", "http://localhost:4200/cb", "\"openid\"", false)))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("role scopes cannot be granted to a client")
    void roleScopeIsRejected() throws Exception {
        String clientId = uniqueClientId();

        mockMvc.perform(post("/admin/clients").with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(clientId, "PUBLIC", "http://localhost:4200/cb", "\"openid\", \"finco:premium\"", false)))
                .andExpect(status().isBadRequest());

        assertNull(registeredClientRepository.findByClientId(clientId));
    }

    @Test
    @DisplayName("plain http redirect URIs are only accepted for localhost")
    void httpRedirectOutsideLocalhostIsRejected() throws Exception {
        mockMvc.perform(post("/admin/clients").with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(uniqueClientId(), "PUBLIC", "http://app.example.com/callback", "\"openid\"", false)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("update replaces redirect URIs and consent policy")
    void updatesClient() throws Exception {
        String clientId = uniqueClientId();
        createPublic(clientId);

        mockMvc.perform(put("/admin/clients/{id}", clientId).with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"clientName": "Renamed", "redirectUris": ["https://finco.example.com/auth/callback"],
                         "postLogoutRedirectUris": [], "scopes": ["openid"], "requireConsent": true}
                        """))
                .andExpect(status().isOk());

        RegisteredClient stored = registeredClientRepository.findByClientId(clientId);
        assertEquals("Renamed", stored.getClientName());
        assertEquals(java.util.Set.of("https://finco.example.com/auth/callback"), stored.getRedirectUris());
        assertTrue(stored.getClientSettings().isRequireAuthorizationConsent());
        assertTrue(stored.getClientSettings().isRequireProofKey(), "PKCE must survive an update");
    }

    @Test
    @DisplayName("delete removes the client and its consents")
    void deletesClientAndItsConsents() throws Exception {
        String clientId = uniqueClientId();
        createPublic(clientId);
        String registeredId = registeredClientRepository.findByClientId(clientId).getId();
        jdbcTemplate.update("INSERT INTO oauth2_authorization_consent (registered_client_id, principal_name, authorities)"
                + " VALUES (?, ?, ?)", registeredId, "someone", "SCOPE_openid");

        mockMvc.perform(delete("/admin/clients/{id}", clientId).with(admin()))
                .andExpect(status().isNoContent());

        assertNull(registeredClientRepository.findByClientId(clientId));
        assertEquals(0, jdbcTemplate.queryForObject(
                "SELECT count(*) FROM oauth2_authorization_consent WHERE registered_client_id = ?", Integer.class,
                registeredId));
        mockMvc.perform(get("/admin/clients/{id}", clientId).with(admin()))
                .andExpect(status().isNotFound());
    }

}
