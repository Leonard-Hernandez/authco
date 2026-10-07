package authco.jwk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import authco.admin.AdminCredentialRepository;
import authco.config.TestContainerConfig;

/**
 * Signing-key rotation against the real stack: Postgres from Testcontainers, the
 * Flyway migrations, the persisted keys and the JwtEncoder / JwtDecoder beans.
 *
 * How the database gets here: TestContainerConfig declares a PostgreSQLContainer
 * bean with @ServiceConnection. Spring starts the container before the context,
 * points the DataSource at its random port, Flyway migrates the empty database,
 * and the container is stopped when the cached context is closed.
 *
 * Every test shares that database, so none of them assumes a starting state:
 * each one rotates or creates the keys it needs.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class JwkRotationIntegrationTest {

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private JwkKeyService jwkKeyService;

    @Autowired
    private AdminCredentialRepository adminCredentialRepository;

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private Jwt sign() {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:8087")
                .subject("integration-test")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims));
    }

    @Test
    @DisplayName("Flyway ran every migration and the admin login was created on startup")
    void migrationsAndAdminCredentials() {
        // admin_credentials only exists from V7; the initializer fills it on startup.
        assertEquals(1, adminCredentialRepository.count());
    }

    @Test
    @DisplayName("after a rotation, new tokens are signed with the new active key")
    void signsWithTheActiveKeyAfterRotation() {
        // Without the JwkSelector in jwtEncoder this throws: the JWKS now holds
        // two RS256 keys and NimbusJwtEncoder refuses to pick one.
        JwkKeyEntity rotated = jwkKeyService.rotate();

        Jwt token = sign();

        assertEquals(rotated.getId(), token.getHeaders().get("kid"));
        assertEquals("integration-test", jwtDecoder.decode(token.getTokenValue()).getSubject());
    }

    @Test
    @DisplayName("a token signed before the rotation still validates (retired, not revoked)")
    void retiredKeyStillValidates() {
        Jwt before = sign();

        jwkKeyService.rotate();

        Jwt decoded = jwtDecoder.decode(before.getTokenValue());
        assertEquals("integration-test", decoded.getSubject());
        assertNotEquals(jwkKeyService.getActiveKeyId(), before.getHeaders().get("kid"));
    }

    @Test
    @DisplayName("revoking a retired key makes the tokens it signed fail at once")
    void revokedKeyStopsValidating() {
        Jwt before = sign();
        String oldKid = (String) before.getHeaders().get("kid");

        jwkKeyService.rotate();
        jwkKeyService.revoke(oldKid);

        assertThrows(JwtException.class, () -> jwtDecoder.decode(before.getTokenValue()));
    }

    @Test
    @DisplayName("the public JWKS endpoint publishes retired keys but not revoked ones")
    @SuppressWarnings("unchecked")
    void jwksEndpointLeavesRevokedKeysOut() throws Exception {
        String retiredKid = jwkKeyService.rotate().getId();
        String revokedKid = jwkKeyService.rotate().getId();
        jwkKeyService.rotate();
        jwkKeyService.revoke(revokedKid);

        String body = mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        List<Map<String, Object>> keys = (List<Map<String, Object>>) objectMapper.readValue(body, Map.class)
                .get("keys");
        List<Object> kids = keys.stream().map(key -> key.get("kid")).toList();

        assertEquals(true, kids.contains(retiredKid));
        assertEquals(false, kids.contains(revokedKid));
        // Public JWKS: only the public modulus/exponent, never the private exponent "d".
        keys.forEach(key -> assertEquals(false, key.containsKey("d")));
    }

}
