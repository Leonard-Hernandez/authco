package authco.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import authco.admin.AdminCredentialRepository;
import authco.config.TestContainerConfig;
import authco.user.repository.UserRepository;

/**
 * The admin user endpoints end to end: HTTP Basic, controller, service, JPA and
 * the real Postgres from Testcontainers, checking what actually lands in the tables.
 *
 * Same annotations as JwkRotationIntegrationTest on purpose: Spring caches the
 * context by its configuration, so both classes reuse one context and one container.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class UserAdminIntegrationTest {

    private static final String ADMIN_PASSWORD = "integration-admin-password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AdminCredentialRepository adminCredentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // The initializer generated a random password nobody knows; swap in one we do.
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

    // The database is shared by every test in the run: unique emails keep them independent.
    private UserEntity newUser() {
        UserEntity user = new UserEntity();
        user.setEmail("user-" + UUID.randomUUID() + "@example.com");
        user.setName("Integration User");
        return userRepository.save(user);
    }

    @Test
    @DisplayName("roles set through the API are exactly what the token customizer reads")
    void rolesReachTheTokenQuery() throws Exception {
        UserEntity user = newUser();

        mockMvc.perform(put("/admin/users/{id}/roles", user.getId()).with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roles\": [\"finco:premium\", \"platform:premium\"]}"))
                .andExpect(status().isOk());

        // findRoleNamesByUserId is the query SubjectTokenCustomizer turns into scopes.
        assertEquals(Set.of("finco:premium", "platform:premium"),
                userRepository.findRoleNamesByUserId(user.getId()));
    }

    @Test
    @DisplayName("an empty role set removes every role")
    void emptyRoleSetClearsRoles() throws Exception {
        UserEntity user = newUser();
        mockMvc.perform(put("/admin/users/{id}/roles", user.getId()).with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roles\": [\"finco:premium\"]}"))
                .andExpect(status().isOk());

        mockMvc.perform(put("/admin/users/{id}/roles", user.getId()).with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roles\": []}"))
                .andExpect(status().isOk());

        assertTrue(userRepository.findRoleNamesByUserId(user.getId()).isEmpty());
    }

    @Test
    @DisplayName("an unknown role is rejected and the stored roles stay untouched")
    void unknownRoleLeavesRolesAsTheyWere() throws Exception {
        UserEntity user = newUser();
        mockMvc.perform(put("/admin/users/{id}/roles", user.getId()).with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roles\": [\"finco:premium\"]}"))
                .andExpect(status().isOk());

        mockMvc.perform(put("/admin/users/{id}/roles", user.getId()).with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roles\": [\"finco:premium\", \"finco:god\"]}"))
                .andExpect(status().isBadRequest());

        assertEquals(Set.of("finco:premium"), userRepository.findRoleNamesByUserId(user.getId()));
    }

    @Test
    @DisplayName("ban and unban are persisted")
    void banAndUnbanArePersisted() throws Exception {
        UserEntity user = newUser();

        mockMvc.perform(post("/admin/users/{id}/ban", user.getId()).with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"reason\": \"abuse\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.banReason").value("abuse"));

        UserEntity banned = userRepository.findById(user.getId()).orElseThrow();
        assertTrue(banned.isBanned());
        assertNotNull(banned.getBannedAt());

        mockMvc.perform(delete("/admin/users/{id}/ban", user.getId()).with(admin()))
                .andExpect(status().isOk());

        UserEntity unbanned = userRepository.findById(user.getId()).orElseThrow();
        assertFalse(unbanned.isBanned());
        assertNull(unbanned.getBanReason());
    }

    @Test
    @DisplayName("editing a user cannot change the email, even if the body carries one")
    void emailIsNotEditable() throws Exception {
        UserEntity user = newUser();

        mockMvc.perform(patch("/admin/users/{id}", user.getId()).with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\": \"Renamed\", \"email\": \"attacker@example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Renamed"));

        UserEntity stored = userRepository.findById(user.getId()).orElseThrow();
        assertEquals("Renamed", stored.getName());
        assertEquals(user.getEmail(), stored.getEmail());
    }

    @Test
    @DisplayName("users can be looked up by exact email")
    void findsUserByEmail() throws Exception {
        UserEntity user = newUser();

        mockMvc.perform(get("/admin/users").param("email", user.getEmail()).with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(user.getId()));
    }

}
