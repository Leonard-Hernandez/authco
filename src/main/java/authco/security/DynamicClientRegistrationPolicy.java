package authco.security;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

/**
 * What an anonymous Dynamic Client Registration request (OIDC {@code /connect/register}
 * or RFC 7591 {@code /oauth2/register}) may ask for. Nobody authenticates these
 * requests, so the only thing that keeps a stranger from registering a client that
 * sends codes to their own site is the redirect URI allowlist.
 *
 * <p>
 * Allowlist entries ({@code authco.dcr.allowed-redirect-uris}) are exact URIs, except
 * for loopback entries written with a wildcard port ({@code http://127.0.0.1:*},
 * {@code http://localhost:*}, {@code http://[::1]:*}), which accept any port as
 * RFC 8252 section 7.3 requires for native apps. Without a path after the port any path
 * is accepted; with one, the path must match exactly.
 */
@Component
public class DynamicClientRegistrationPolicy {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2";

    private static final Pattern LOOPBACK_ANY_PORT = Pattern
            .compile("^http://(127\\.0\\.0\\.1|localhost|\\[::1\\]):\\*(/.*)?$");

    private static final Set<AuthorizationGrantType> ALLOWED_GRANT_TYPES = Set.of(
            AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN);

    private final List<String> allowedRedirectUris;

    public DynamicClientRegistrationPolicy(
            @Value("${authco.dcr.allowed-redirect-uris}") List<String> allowedRedirectUris) {
        this.allowedRedirectUris = allowedRedirectUris;
    }

    /**
     * Every requested redirect URI must be on the allowlist, and there must be at
     * least one: every client this endpoint creates runs the authorization code flow.
     */
    public void validateRedirectUris(List<String> redirectUris) {
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw invalidRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI, "redirect_uris");
        }
        for (String redirectUri : redirectUris) {
            if (!isAllowed(redirectUri)) {
                throw invalidRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI, "redirect_uris");
            }
        }
    }

    /**
     * Narrows a freshly converted client to what anonymous registration grants: the
     * allowed scopes, the authorization code (plus refresh token) grant, PKCE and
     * short-lived tokens. Rejects any other grant type rather than silently dropping
     * it, so the client learns it cannot use it.
     */
    public RegisteredClient apply(RegisteredClient registeredClient) {
        if (!ALLOWED_GRANT_TYPES.containsAll(registeredClient.getAuthorizationGrantTypes())) {
            throw invalidRegistration("invalid_client_metadata", "grant_types");
        }

        return RegisteredClient.from(registeredClient)
                .scopes(scopes -> scopes.retainAll(ClientScopes.ALLOWED))
                .clientSettings(ClientSettings.withSettings(registeredClient.getClientSettings().getSettings())
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.withSettings(registeredClient.getTokenSettings().getSettings())
                        .accessTokenTimeToLive(TokenLifetimes.ACCESS_TOKEN)
                        .refreshTokenTimeToLive(TokenLifetimes.REFRESH_TOKEN)
                        .build())
                .build();
    }

    boolean isAllowed(String redirectUri) {
        URI candidate;
        try {
            candidate = new URI(redirectUri);
        } catch (URISyntaxException | NullPointerException ex) {
            return false;
        }
        if (candidate.getFragment() != null || candidate.getUserInfo() != null) {
            return false;
        }

        for (String allowed : allowedRedirectUris) {
            if (allowed.equals(redirectUri) || matchesLoopbackAnyPort(allowed, candidate)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesLoopbackAnyPort(String allowed, URI candidate) {
        Matcher matcher = LOOPBACK_ANY_PORT.matcher(allowed);
        if (!matcher.matches()) {
            return false;
        }
        String host = matcher.group(1);
        String path = matcher.group(2);

        if (!"http".equals(candidate.getScheme()) || !host.equalsIgnoreCase(candidate.getHost())) {
            return false;
        }
        return path == null || path.equals(candidate.getRawPath());
    }

    private static OAuth2AuthenticationException invalidRegistration(String errorCode, String fieldName) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(errorCode, "Invalid Client Registration: " + fieldName, ERROR_URI));
    }

}
