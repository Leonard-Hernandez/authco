package authco.admin;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import authco.jwk.JwkKeyEntity;
import authco.jwk.JwkKeyService;
import authco.jwk.exception.ActiveKeyRevocationException;
import authco.user.UserAdminService;
import authco.user.UserEntity;
import authco.user.exception.UnknownRoleException;
import authco.user.exception.UserNotFoundException;

@WebMvcTest(controllers = { AdminUserController.class, AdminJwkController.class })
@Import({ AdminSecurityConfig.class, AdminApiTest.PasswordEncoderConfig.class })
@TestPropertySource(properties = {
        "GOOGLE_CLIENT_ID=test-client",
        "GOOGLE_CLIENT_SECRET=test-secret" })
class AdminApiTest {

    private static final String PASSWORD = "correct-password";

    @TestConfiguration
    static class PasswordEncoderConfig {
        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private AdminCredentialRepository adminCredentialRepository;

    @MockitoBean
    private UserAdminService userAdminService;

    @MockitoBean
    private JwkKeyService jwkKeyService;

    @BeforeEach
    void setUp() {
        AdminCredentialEntity admin = new AdminCredentialEntity();
        admin.setUsername("admin");
        admin.setPasswordHash(passwordEncoder.encode(PASSWORD));
        when(adminCredentialRepository.findById("admin")).thenReturn(Optional.of(admin));
    }

    private static UserEntity user(String id) {
        UserEntity user = new UserEntity();
        user.setId(id);
        user.setEmail("user@example.com");
        return user;
    }

    @Test
    @DisplayName("without credentials the API answers 401 and asks for Basic auth")
    void rejectsAnonymous() throws Exception {
        mockMvc.perform(get("/admin/users"))
                .andExpect(status().isUnauthorized());
        verify(userAdminService, never()).list(any());
    }

    @Test
    @DisplayName("a wrong password is rejected")
    void rejectsWrongPassword() throws Exception {
        mockMvc.perform(get("/admin/users").with(httpBasic("admin", "wrong")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("the Swagger spec is behind the same credentials")
    void protectsApiDocs() throws Exception {
        mockMvc.perform(get("/v3/api-docs/admin"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("valid credentials list users")
    void listsUsers() throws Exception {
        when(userAdminService.list(Optional.empty())).thenReturn(List.of(user("u1")));

        mockMvc.perform(get("/admin/users").with(httpBasic("admin", PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value("u1"));
    }

    @Test
    @DisplayName("an unknown user is a 404 problem detail")
    void unknownUserIs404() throws Exception {
        when(userAdminService.get("missing")).thenThrow(new UserNotFoundException("missing"));

        mockMvc.perform(get("/admin/users/missing").with(httpBasic("admin", PASSWORD)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.detail").value("User not found: missing"));
    }

    @Test
    @DisplayName("banning without a reason is a 400 and bans nobody")
    void banRequiresReason() throws Exception {
        mockMvc.perform(post("/admin/users/u1/ban").with(httpBasic("admin", PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"reason\": \"\"}"))
                .andExpect(status().isBadRequest());
        verify(userAdminService, never()).ban(any(), any());
    }

    @Test
    @DisplayName("banning with a reason returns the banned user")
    void bansUser() throws Exception {
        UserEntity banned = user("u1");
        banned.setBannedAt(java.time.Instant.now());
        banned.setBanReason("abuse");
        when(userAdminService.ban("u1", "abuse")).thenReturn(banned);

        mockMvc.perform(post("/admin/users/u1/ban").with(httpBasic("admin", PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"reason\": \"abuse\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.banReason").value("abuse"));
    }

    @Test
    @DisplayName("assigning a role that does not exist is a 400")
    void unknownRoleIs400() throws Exception {
        when(userAdminService.replaceRoles(eq("u1"), anySet()))
                .thenThrow(new UnknownRoleException(Set.of("finco:god")));

        mockMvc.perform(put("/admin/users/u1/roles").with(httpBasic("admin", PASSWORD))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roles\": [\"finco:god\"]}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("rotating keys answers 201 with the new active key")
    void rotatesKey() throws Exception {
        JwkKeyEntity key = new JwkKeyEntity();
        key.setId("new-kid");
        key.setAlgorithm("RS256");
        key.setActive(true);
        when(jwkKeyService.rotate()).thenReturn(key);

        mockMvc.perform(post("/admin/jwks/rotate").with(httpBasic("admin", PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.kid").value("new-kid"))
                .andExpect(jsonPath("$.active").value(true));
    }

    @Test
    @DisplayName("revoking the active key is a 409")
    void revokingActiveKeyIs409() throws Exception {
        when(jwkKeyService.revoke("current")).thenThrow(new ActiveKeyRevocationException("current"));

        mockMvc.perform(post("/admin/jwks/current/revoke").with(httpBasic("admin", PASSWORD)))
                .andExpect(status().isConflict());
    }

}
