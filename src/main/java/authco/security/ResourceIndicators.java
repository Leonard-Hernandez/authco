package authco.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * RFC 8707 resource indicators: which {@code resource} values a client may ask for.
 *
 * <p>
 * {@code authco.resources} lists the canonical URIs of the resource servers tokens can
 * be issued for. A requested {@code resource} that is one of them, or a URI below one
 * of them (an MCP client may send the URL of the MCP endpoint itself), maps to that
 * canonical URI. No {@code resource} maps to the first entry. Anything else is
 * {@code invalid_target}, at the authorization endpoint already, so the user is never
 * asked to consent to a request that cannot get a token.
 */
@Component
public class ResourceIndicators {

    /** RFC 8707 resource indicator parameter. */
    static final String RESOURCE = "resource";

    static final String INVALID_TARGET = "invalid_target";

    private static final String INVALID_TARGET_URI = "https://datatracker.ietf.org/doc/html/rfc8707#section-2";

    private final List<String> resources;

    public ResourceIndicators(@Value("${authco.resources}") List<String> resources) {
        this.resources = resources;
    }

    /** The canonical resource URIs (token audiences) the requested resources map to. */
    public Set<String> audiencesFor(Set<String> requestedResources) {
        Set<String> audiences = new LinkedHashSet<>();
        if (requestedResources.isEmpty()) {
            if (!resources.isEmpty()) {
                audiences.add(resources.getFirst());
            }
            return audiences;
        }
        for (String requested : requestedResources) {
            audiences.add(resources.stream()
                    .filter(resource -> matchesResource(requested, resource))
                    .findFirst()
                    .orElseThrow(() -> invalidTarget("The requested resource is not served by this authorization server")));
        }
        return audiences;
    }

    /**
     * Authorization endpoint validator: rejects an unknown {@code resource} with
     * {@code invalid_target} on the client's redirect URI, before consent and before
     * any code is issued. Runs after the stock validators, so the redirect URI is
     * already trusted.
     */
    public void validateAuthorizationRequest(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken request = context.getAuthentication();
        try {
            audiencesFor(requestedIn(request.getAdditionalParameters()));
        } catch (OAuth2AuthenticationException ex) {
            String redirectUri = StringUtils.hasText(request.getRedirectUri()) ? request.getRedirectUri()
                    : context.getRegisteredClient().getRedirectUris().iterator().next();
            OAuth2AuthorizationCodeRequestAuthenticationToken result = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                    request.getAuthorizationUri(), request.getClientId(), (Authentication) request.getPrincipal(),
                    redirectUri, request.getState(), request.getScopes(), request.getAdditionalParameters());
            result.setAuthenticated(true);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(ex.getError(), result);
        }
    }

    static OAuth2AuthenticationException invalidTarget(String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(INVALID_TARGET, description, INVALID_TARGET_URI));
    }

    // Repeated parameters arrive as String[] from the request and as a list once the
    // authorization request has been stored and read back.
    static Set<String> requestedIn(Map<String, Object> parameters) {
        Set<String> requested = new LinkedHashSet<>();
        Object value = parameters.get(RESOURCE);
        if (value instanceof String resource) {
            requested.add(resource);
        } else if (value instanceof String[] values) {
            requested.addAll(Arrays.asList(values));
        } else if (value instanceof Collection<?> values) {
            values.forEach(resource -> requested.add(resource.toString()));
        }
        return requested;
    }

    private static boolean matchesResource(String requested, String resource) {
        String base = Uris.stripTrailingSlash(resource);
        String candidate = Uris.stripTrailingSlash(requested);
        // A path boundary is required: .../v1 must not match .../v1-admin.
        return candidate.equals(base) || candidate.startsWith(base + "/");
    }

}
