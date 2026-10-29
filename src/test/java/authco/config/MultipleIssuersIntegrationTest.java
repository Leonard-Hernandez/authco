package authco.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * One authco shared by two apps on different origins: each origin in authco.issuer is
 * its own issuer, anything else is served as the first one. Barberco is configured
 * with an explicit default port, uppercase host and trailing slash on purpose: it must
 * still match its origin.
 */
@SpringBootTest(properties = "authco.issuer=https://restauco.test/authco,https://Barberco.test:443/authco/")
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class MultipleIssuersIntegrationTest {

    private static final String BARBERCO = "https://barberco.test/authco";
    private static final String CLIENT_ID = "barberco-backend";
    private static final String REDIRECT_URI = "https://barberco.test/login/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void registerClient() {
        if (registeredClientRepository.findByClientId(CLIENT_ID) != null) {
            return;
        }
        registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build());
    }

    @Test
    @DisplayName("each allowed origin gets its own issuer in the discovery document")
    void issuerFollowsAllowedOrigin() throws Exception {
        mockMvc.perform(discovery("https://barberco.test:443"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(BARBERCO))
                .andExpect(jsonPath("$.authorization_endpoint").value(BARBERCO + "/oauth2/authorize"));

        mockMvc.perform(discovery("https://restauco.test:443"))
                .andExpect(jsonPath("$.issuer").value("https://restauco.test/authco"));
    }

    @Test
    @DisplayName("an uppercase Host still matches its (normalized) issuer")
    void hostCaseIgnored() throws Exception {
        mockMvc.perform(discovery("https://BARBERCO.test:443"))
                .andExpect(jsonPath("$.issuer").value(BARBERCO));
    }

    @Test
    @DisplayName("an origin outside the list (in-cluster call, forged Host) is served as the first issuer")
    void unknownOriginFallsBackToFirstIssuer() throws Exception {
        mockMvc.perform(discovery("http://authco:8087"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://restauco.test/authco"));

        mockMvc.perform(discovery("https://evil.test:443"))
                .andExpect(jsonPath("$.issuer").value("https://restauco.test/authco"))
                .andExpect(jsonPath("$.token_endpoint").value("https://restauco.test/authco/oauth2/token"));
    }

    @Test
    @DisplayName("tokens keep the issuer of the authorization's origin on back-channel code exchange and refresh")
    void backChannelTokensKeepAuthorizationIssuer() throws Exception {
        String location = mockMvc.perform(get("https://barberco.test:443/authco/oauth2/authorize").contextPath("/authco")
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("code_challenge", CHALLENGE)
                .queryParam("code_challenge_method", "S256")
                // As after a federated login: the ID token needs the factor's auth_time.
                .with(authentication(new TestingAuthenticationToken("someone", null, List.of(
                        FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY))))))
                .andExpect(status().isFound())
                .andReturn().getResponse().getHeader(HttpHeaders.LOCATION);
        String code = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");

        // App B's backend calls authco directly, not through its public origin.
        Map<?, ?> tokens = token(Map.of(
                "grant_type", "authorization_code",
                "code", code,
                "redirect_uri", REDIRECT_URI,
                "code_verifier", VERIFIER));
        assertThat(issuerOf((String) tokens.get("access_token"))).isEqualTo(BARBERCO);
        assertThat(issuerOf((String) tokens.get("id_token"))).isEqualTo(BARBERCO);

        Map<?, ?> refreshed = token(Map.of(
                "grant_type", "refresh_token",
                "refresh_token", tokens.get("refresh_token")));
        assertThat(issuerOf((String) refreshed.get("access_token"))).isEqualTo(BARBERCO);
    }

    private Map<?, ?> token(Map<String, Object> parameters) throws Exception {
        MockHttpServletRequestBuilder request = post("http://authco:8087/authco/oauth2/token").contextPath("/authco")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, "Basic "
                        + Base64.getEncoder().encodeToString((CLIENT_ID + ":secret").getBytes(StandardCharsets.UTF_8)));
        parameters.forEach((name, value) -> request.param(name, value.toString()));
        String body = mockMvc.perform(request)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JSON.readValue(body, Map.class);
    }

    private static String issuerOf(String jwt) throws Exception {
        byte[] payload = Base64.getUrlDecoder().decode(jwt.split("\\.")[1]);
        return (String) JSON.readValue(payload, Map.class).get("iss");
    }

    // Explicit port: MockMvc would otherwise put an https URL on port 80.
    private static MockHttpServletRequestBuilder discovery(String origin) {
        return get(origin + "/authco/.well-known/openid-configuration").contextPath("/authco");
    }

}
