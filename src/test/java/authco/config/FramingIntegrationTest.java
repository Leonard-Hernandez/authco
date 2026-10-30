package authco.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * No page of authco can be framed, not even by the SPA origins allowed by CORS: a
 * frameable login or consent page is a clickjacking target.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class FramingIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @ParameterizedTest
    @ValueSource(strings = { "/login", "/oauth2/consent", "/oauth2/authorize" })
    @DisplayName("login, consent and authorize answer with X-Frame-Options: DENY and no frame-ancestors")
    void pagesAreNotFrameable(String path) throws Exception {
        MockHttpServletResponse response = mockMvc.perform(get(path)
                .queryParam("client_id", "unknown")
                .queryParam("response_type", "code")
                .queryParam("prompt", "none")
                .with(user("someone")))
                .andReturn().getResponse();

        assertThat(response.getHeader("X-Frame-Options")).isEqualTo("DENY");
        // No CSP header at all is fine too; it just must not allow framing.
        assertThat(String.valueOf(response.getHeader("Content-Security-Policy"))).doesNotContain("frame-ancestors");
    }

}
