package authco.config;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import authco.security.Uris;

/**
 * The issuers authco answers as ({@code authco.issuer}), normalized so that equivalent
 * spellings compare equal: lowercase scheme and host, no default port (:443 for
 * https, :80 for http) and no trailing slash. {@code https://Example.com:443/authco/}
 * and {@code https://example.com/authco} are the same issuer.
 */
public final class Issuers {

    private final List<String> issuers;

    public Issuers(List<String> configured) {
        if (configured.isEmpty()) {
            throw new IllegalArgumentException("authco.issuer must name at least one issuer");
        }
        this.issuers = configured.stream().map(Issuers::normalize).distinct().toList();
    }

    public List<String> all() {
        return issuers;
    }

    public String first() {
        return issuers.getFirst();
    }

    /** Several issuers: each request (and each authorization) gets the one of its origin. */
    public boolean isMultiple() {
        return issuers.size() > 1;
    }

    /** The configured issuer equal to the given one, once both are normalized. */
    public Optional<String> find(String issuer) {
        String normalized = normalize(issuer);
        return issuers.stream().filter(normalized::equals).findFirst();
    }

    /**
     * The configured issuer an endpoint URL lives under, e.g. the issuer of
     * {@code https://barberco.test/authco/oauth2/authorize}.
     */
    public Optional<String> issuerOf(String endpointUrl) {
        String normalized = normalize(endpointUrl);
        return issuers.stream().filter(issuer -> normalized.startsWith(issuer + "/")).findFirst();
    }

    static String normalize(String uri) {
        URI parsed = URI.create(uri.trim());
        String scheme = parsed.getScheme().toLowerCase(Locale.ROOT);
        StringBuilder normalized = new StringBuilder(scheme).append("://")
                .append(parsed.getHost().toLowerCase(Locale.ROOT));
        int port = parsed.getPort();
        boolean defaultPort = port == -1 || ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);
        if (!defaultPort) {
            normalized.append(':').append(port);
        }
        normalized.append(Uris.stripTrailingSlash(parsed.getRawPath() == null ? "" : parsed.getRawPath()));
        return normalized.toString();
    }

}
