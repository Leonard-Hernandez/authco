package authco.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import authco.user.UserEntity;
import authco.user.repository.UserRepository;

/**
 * Shapes the tokens: subject, user claims, role scopes and, for access tokens, the
 * RFC 8707 audience.
 *
 * <p>
 * {@code authco.resources} lists the canonical URIs of the resource servers tokens can
 * be issued for. A requested {@code resource} that is one of them, or a URI below one
 * of them (an MCP client may send the URL of the MCP endpoint itself), yields that
 * canonical URI as audience. A request without {@code resource} gets the first entry.
 * Anything else is rejected with {@code invalid_target}.
 */
@Component
public class SubjectTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    /** RFC 8707 resource indicator parameter. */
    static final String RESOURCE = "resource";

    static final String INVALID_TARGET = "invalid_target";

    private static final String INVALID_TARGET_URI = "https://datatracker.ietf.org/doc/html/rfc8707#section-2";

    private final UserRepository userRepository;
    private final List<String> resources;

    public SubjectTokenCustomizer(UserRepository userRepository,
            @Value("${authco.resources}") List<String> resources) {
        this.userRepository = userRepository;
        this.resources = resources;
    }

    @Override
    public void customize(JwtEncodingContext context) {

        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            addAudiences(context);
        }

        Authentication principal = context.getPrincipal();

        if (principal.getPrincipal() instanceof OAuth2User oAuth2User) {

            String userId = oAuth2User.getName();

            UserEntity user = userRepository.findById(userId)
                    .orElseThrow(() -> new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT));

            if (user.isBanned()) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }

            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                if (context.getAuthorizedScopes().contains(OidcScopes.EMAIL)) {
                    context.getClaims().claim(StandardClaimNames.EMAIL, user.getEmail())
                            .claim(StandardClaimNames.EMAIL_VERIFIED, user.isEmailVerified());
                }

                if (context.getAuthorizedScopes().contains(OidcScopes.PROFILE)) {
                    if (user.getName() != null && !user.getName().isBlank()) {
                        context.getClaims().claim(StandardClaimNames.NAME, user.getName());
                    }
                }
            }

            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

                Set<String> grantedScopes = new HashSet<>(context.getAuthorizedScopes());
                grantedScopes.retainAll(ClientScopes.ALLOWED);
                grantedScopes
                        .addAll(userRepository.findRoleNamesByUserId(userId));

                context.getClaims().claim(OAuth2ParameterNames.SCOPE, grantedScopes);

            }

            context.getClaims().subject(user.getId());

        }

    }

    /**
     * Adds the resource servers the token is meant for to {@code aud}, next to the
     * client_id Spring Authorization Server already put there. The token request's
     * {@code resource} wins; without one (e.g. a refresh that omits it), the one sent
     * to the authorization endpoint is used.
     */
    private void addAudiences(JwtEncodingContext context) {
        Set<String> requestedResources = new LinkedHashSet<>();
        if (context.getAuthorizationGrant() instanceof OAuth2AuthorizationGrantAuthenticationToken grant) {
            collectResources(grant.getAdditionalParameters(), requestedResources);
        }
        OAuth2Authorization authorization = context.getAuthorization();
        if (requestedResources.isEmpty() && authorization != null) {
            OAuth2AuthorizationRequest authorizationRequest = authorization
                    .getAttribute(OAuth2AuthorizationRequest.class.getName());
            if (authorizationRequest != null) {
                collectResources(authorizationRequest.getAdditionalParameters(), requestedResources);
            }
        }

        Set<String> resourceAudiences = audiencesFor(requestedResources);

        context.getClaims().claims(claims -> {
            Set<String> audiences = new LinkedHashSet<>();
            audiences.add(context.getRegisteredClient().getClientId());
            Object current = claims.get(JwtClaimNames.AUD);
            if (current instanceof Collection<?> values) {
                values.forEach(value -> audiences.add(value.toString()));
            } else if (current != null) {
                audiences.add(current.toString());
            }
            audiences.addAll(resourceAudiences);
            // Mutable list on purpose: the claims are persisted with the authorization and
            // Jackson's allowlist rejects JDK immutable collections when reading them back.
            claims.put(JwtClaimNames.AUD, new ArrayList<>(audiences));
        });
    }

    private Set<String> audiencesFor(Set<String> requestedResources) {
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
                    .orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error(INVALID_TARGET,
                            "The requested resource is not served by this authorization server",
                            INVALID_TARGET_URI))));
        }
        return audiences;
    }

    private static boolean matchesResource(String requested, String resource) {
        String base = stripTrailingSlash(resource);
        String candidate = stripTrailingSlash(requested);
        // A path boundary is required: .../v1 must not match .../v1-admin.
        return candidate.equals(base) || candidate.startsWith(base + "/");
    }

    private static String stripTrailingSlash(String uri) {
        return uri.endsWith("/") ? uri.substring(0, uri.length() - 1) : uri;
    }

    // Repeated parameters arrive as String[] from the request and as a list once the
    // authorization request has been stored and read back.
    private static void collectResources(Map<String, Object> parameters, Set<String> into) {
        Object value = parameters.get(RESOURCE);
        if (value instanceof String resource) {
            into.add(resource);
        } else if (value instanceof String[] resources) {
            into.addAll(Arrays.asList(resources));
        } else if (value instanceof Collection<?> resources) {
            resources.forEach(resource -> into.add(resource.toString()));
        }
    }

}
