package authco.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Silent renewal: the SPA loads /oauth2/authorize?prompt=none in a hidden iframe. The
 * pages must be frameable by the SPA origin (authco.cors.allowed-origins) and, without
 * a session, the answer must reach the SPA's redirect URI as error=login_required.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class SilentAuthenticationIntegrationTest {

    private static final String CLIENT_ID = "silent-auth-spa";
    private static final String REDIRECT_URI = "http://localhost:4200/auth/callback";
    private static final String FRAME_ANCESTORS = "frame-ancestors 'self' http://localhost:4200";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @BeforeEach
    void registerClient() {
        if (registeredClientRepository.findByClientId(CLIENT_ID) != null) {
            return;
        }
        registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build());
    }

    private static MockHttpServletRequestBuilder authorize() {
        return get("/oauth2/authorize")
                .accept(MediaType.TEXT_HTML)
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "state-123")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256");
    }

    @Test
    @DisplayName("prompt=none without a session redirects to the SPA with error=login_required")
    void promptNoneWithoutSessionReturnsLoginRequired() throws Exception {
        String location = mockMvc.perform(authorize().queryParam("prompt", "none"))
                .andExpect(status().isFound())
                .andExpect(header().string("Content-Security-Policy", FRAME_ANCESTORS))
                .andExpect(header().doesNotExist("X-Frame-Options"))
                .andReturn().getResponse().getHeader(HttpHeaders.LOCATION);

        assertThat(location).startsWith(REDIRECT_URI + "?")
                .contains("error=login_required")
                .contains("state=state-123");
    }

    @Test
    @DisplayName("prompt=none with a session issues the code without any page")
    void promptNoneWithSessionIssuesCode() throws Exception {
        String location = mockMvc.perform(authorize().queryParam("prompt", "none").with(user("someone")))
                .andExpect(status().isFound())
                .andReturn().getResponse().getHeader(HttpHeaders.LOCATION);

        assertThat(location).startsWith(REDIRECT_URI + "?code=").contains("state=state-123");
    }

    @Test
    @DisplayName("the login page can be framed by the SPA origin too")
    void loginPageFrameableBySpa() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(header().string("Content-Security-Policy", FRAME_ANCESTORS))
                .andExpect(header().doesNotExist("X-Frame-Options"));
    }

}
