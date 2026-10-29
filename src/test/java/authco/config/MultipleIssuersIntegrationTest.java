package authco.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * One authco shared by two apps on different origins: each origin in authco.issuer is
 * its own issuer, anything else is served as the first one.
 */
@SpringBootTest(properties = "authco.issuer=https://restauco.test/authco,https://barberco.test/authco")
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class MultipleIssuersIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("each allowed origin gets its own issuer in the discovery document")
    void issuerFollowsAllowedOrigin() throws Exception {
        mockMvc.perform(discovery("https://barberco.test:443"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://barberco.test/authco"))
                .andExpect(jsonPath("$.authorization_endpoint").value("https://barberco.test/authco/oauth2/authorize"));

        mockMvc.perform(discovery("https://restauco.test:443"))
                .andExpect(jsonPath("$.issuer").value("https://restauco.test/authco"));
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

    // Explicit port: MockMvc would otherwise put an https URL on port 80.
    private static MockHttpServletRequestBuilder discovery(String origin) {
        return get(origin + "/authco/.well-known/openid-configuration").contextPath("/authco");
    }

}
