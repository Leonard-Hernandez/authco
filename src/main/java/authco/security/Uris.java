package authco.security;

import java.util.Locale;
import java.util.Set;

/**
 * URI helpers shared by every place that compares or vets URIs (issuers, resource
 * indicators, redirect URIs), so they all agree on what a trailing slash and a
 * loopback host are.
 */
public final class Uris {

    // RFC 8252 section 7.3: the loopback interface, as URI#getHost() returns it.
    private static final Set<String> LOOPBACK_HOSTS = Set.of("127.0.0.1", "[::1]", "localhost");

    // RFC 6761: *.localhost always resolves to loopback, e.g. the finco.localhost host
    // of the local Kubernetes ingress.
    private static final String LOCALHOST_DOMAIN_SUFFIX = ".localhost";

    private Uris() {
    }

    /** {@code https://a.test/x/} and {@code https://a.test/x} name the same thing. */
    public static String stripTrailingSlash(String uri) {
        return uri.endsWith("/") ? uri.substring(0, uri.length() - 1) : uri;
    }

    /**
     * Loopback as RFC 8252 defines it for native apps: {@code 127.0.0.1}, {@code [::1]}
     * and {@code localhost} (case-insensitive). What anonymous Dynamic Client
     * Registration accepts on any port.
     */
    public static boolean isLoopbackHost(String host) {
        return host != null && LOOPBACK_HOSTS.contains(host.toLowerCase(Locale.ROOT));
    }

    /**
     * Loopback plus any {@code *.localhost} name (RFC 6761). Only for URIs an admin
     * registers (local development behind a local ingress); anonymous registration
     * sticks to {@link #isLoopbackHost(String)}.
     */
    public static boolean isLocalDevelopmentHost(String host) {
        return isLoopbackHost(host) || (host != null && host.toLowerCase(Locale.ROOT).endsWith(LOCALHOST_DOMAIN_SUFFIX));
    }

}
