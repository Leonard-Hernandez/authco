package authco.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RegistrationRateLimitFilterTest {

    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    private final MutableClock clock = new MutableClock();

    private final RegistrationRateLimitFilter filter = new RegistrationRateLimitFilter(2, Duration.ofMinutes(10),
            clock);

    private static final class MutableClock extends Clock {

        private Instant now = START;

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

    }

    private MockHttpServletResponse register(String remoteAddr) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/register");
        request.setRemoteAddr(remoteAddr);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    @Test
    @DisplayName("the N+1-th registration from one address within the window gets 429 with Retry-After")
    void limitsPerAddress() throws Exception {
        assertEquals(200, register("203.0.113.7").getStatus());
        assertEquals(200, register("203.0.113.7").getStatus());

        clock.now = START.plusSeconds(60);
        MockHttpServletResponse limited = register("203.0.113.7");
        assertEquals(429, limited.getStatus());
        assertEquals("540", limited.getHeader("Retry-After"));

        // Other addresses have their own budget.
        assertEquals(200, register("198.51.100.1").getStatus());
    }

    @Test
    @DisplayName("a new window starts once the previous one has elapsed")
    void windowResets() throws Exception {
        register("203.0.113.7");
        register("203.0.113.7");
        assertEquals(429, register("203.0.113.7").getStatus());

        clock.now = START.plus(Duration.ofMinutes(10));
        assertEquals(200, register("203.0.113.7").getStatus());
    }

    @Test
    @DisplayName("only registrations (POST) count")
    void readsAreNotLimited() throws Exception {
        for (int i = 0; i < 5; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/connect/register");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new MockFilterChain());
            assertNull(response.getHeader("Retry-After"));
        }
        assertEquals(200, register("127.0.0.1").getStatus());
    }

}
