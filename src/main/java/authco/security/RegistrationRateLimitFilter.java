package authco.security;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Per client IP limit on anonymous Dynamic Client Registration (POST to
 * {@code /connect/register} and {@code /oauth2/register}): nobody authenticates these
 * requests, and each one stores a client and may hash a secret with bcrypt.
 *
 * <p>
 * Fixed window, in memory: each replica counts on its own, which is enough to stop a
 * single caller from filling the table or burning CPU. Over the limit the answer is
 * {@code 429} with {@code Retry-After}. The client IP is
 * {@link HttpServletRequest#getRemoteAddr()}, i.e. X-Forwarded-For only when it comes
 * from a trusted proxy.
 */
public class RegistrationRateLimitFilter extends OncePerRequestFilter {

    // Expired windows are dropped once the map grows past this many addresses.
    private static final int PURGE_THRESHOLD = 10_000;

    private final int maxRequests;
    private final Duration window;
    private final Clock clock;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RegistrationRateLimitFilter(int maxRequests, Duration window, Clock clock) {
        this.maxRequests = maxRequests;
        this.window = window;
        this.clock = clock;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Instant now = clock.instant();
        if (windows.size() > PURGE_THRESHOLD) {
            windows.values().removeIf(expired -> !now.isBefore(expired.end()));
        }

        Window current = windows.compute(request.getRemoteAddr(), (address, previous) -> {
            if (previous == null || !now.isBefore(previous.end())) {
                return new Window(now.plus(window), 1);
            }
            return new Window(previous.end(), previous.count() + 1);
        });

        if (current.count() > maxRequests) {
            long retryAfter = Math.max(1, Duration.between(now, current.end()).toSeconds());
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retryAfter));
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"too_many_requests\","
                    + "\"error_description\":\"Too many client registrations from this address\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private record Window(Instant end, int count) {
    }

}
