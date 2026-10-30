package authco.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;

/**
 * X-Forwarded-* reach the application only from a trusted proxy (Tomcat's
 * RemoteIpValve, which MockMvc bypasses, hence a real port). The login redirect is an
 * absolute URL built from the request's scheme and host, so it shows which origin the
 * application believes the request came through.
 */
class ForwardedHeadersIntegrationTest {

    private static String loginRedirect(int port) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/authco/oauth2/consent"))
                .header(HttpHeaders.ACCEPT, "text/html")
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", "evil.test")
                .header("X-Forwarded-Port", "443")
                .build();
        HttpResponse<Void> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(302);
        return response.headers().firstValue(HttpHeaders.LOCATION).orElseThrow();
    }

    @Nested
    @SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT,
            // The test client connects from loopback: trust some other address only.
            properties = "server.tomcat.remoteip.internal-proxies=10.255.255.254/32")
    @Import(TestContainerConfig.class)
    @ActiveProfiles("test")
    class FromUntrustedPeer {

        @LocalServerPort
        private int port;

        @Test
        @DisplayName("a caller that is not a trusted proxy cannot change the scheme or host")
        void forwardedHeadersIgnored() throws Exception {
            assertThat(loginRedirect(port)).isEqualTo("http://127.0.0.1:" + port + "/authco/login");
        }

    }

    @Nested
    @SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
    @Import(TestContainerConfig.class)
    @ActiveProfiles("test")
    class FromTrustedProxy {

        @LocalServerPort
        private int port;

        @Test
        @DisplayName("a trusted proxy (loopback by default) sets the public scheme and host")
        void forwardedHeadersApplied() throws Exception {
            assertThat(loginRedirect(port)).isEqualTo("https://evil.test/authco/login");
        }

    }

}
