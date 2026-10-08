package authco.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * What a browser asks before a SPA on another origin calls the authorization
 * server from JavaScript. The allowed origin comes from authco.cors.allowed-origins.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class CorsIntegrationTest {

    private static final String SPA_ORIGIN = "http://localhost:4200";

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("the SPA may POST to the token endpoint (preflight is approved)")
    void tokenPreflightAllowedForSpa() throws Exception {
        mockMvc.perform(options("/oauth2/token")
                .header(HttpHeaders.ORIGIN, SPA_ORIGIN)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Content-Type"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, SPA_ORIGIN))
                // No cookies cross-origin: the code exchange is proven by PKCE, not by the session.
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
    }

    @Test
    @DisplayName("the SPA can read the JWKS and the discovery document")
    void publicEndpointsReadableFromSpa() throws Exception {
        mockMvc.perform(get("/oauth2/jwks").header(HttpHeaders.ORIGIN, SPA_ORIGIN))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, SPA_ORIGIN));

        mockMvc.perform(get("/.well-known/openid-configuration").header(HttpHeaders.ORIGIN, SPA_ORIGIN))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, SPA_ORIGIN));
    }

    @Test
    @DisplayName("any other origin is refused")
    void otherOriginsRefused() throws Exception {
        mockMvc.perform(options("/oauth2/token")
                .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    @DisplayName("same host and port over https is a different origin")
    void schemeIsPartOfTheOrigin() throws Exception {
        mockMvc.perform(options("/oauth2/token")
                .header(HttpHeaders.ORIGIN, "https://localhost:4200")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isForbidden());
    }

}
