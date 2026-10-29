package authco.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
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
 * RFC 8707 audience (see {@link ResourceIndicators}).
 */
@Component
public class SubjectTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final UserRepository userRepository;
    private final ResourceIndicators resourceIndicators;

    public SubjectTokenCustomizer(UserRepository userRepository, ResourceIndicators resourceIndicators) {
        this.userRepository = userRepository;
        this.resourceIndicators = resourceIndicators;
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
     * client_id Spring Authorization Server already put there.
     *
     * <p>
     * Resources sent to the authorization endpoint are what the user authorized: a
     * token request (code exchange or refresh) may narrow them with {@code resource},
     * never widen them, and without {@code resource} gets all of them. Only when the
     * authorization request named none is the token request's {@code resource} taken
     * as is (RFC 8707 allows it on either endpoint).
     */
    private void addAudiences(JwtEncodingContext context) {
        Set<String> requestedResources = Set.of();
        if (context.getAuthorizationGrant() instanceof OAuth2AuthorizationGrantAuthenticationToken grant) {
            requestedResources = ResourceIndicators.requestedIn(grant.getAdditionalParameters());
        }
        Set<String> authorizedResources = Set.of();
        OAuth2Authorization authorization = context.getAuthorization();
        if (authorization != null) {
            OAuth2AuthorizationRequest authorizationRequest = authorization
                    .getAttribute(OAuth2AuthorizationRequest.class.getName());
            if (authorizationRequest != null) {
                authorizedResources = ResourceIndicators.requestedIn(authorizationRequest.getAdditionalParameters());
            }
        }

        Set<String> resourceAudiences;
        if (authorizedResources.isEmpty()) {
            resourceAudiences = resourceIndicators.audiencesFor(requestedResources);
        } else {
            Set<String> authorizedAudiences = resourceIndicators.audiencesFor(authorizedResources);
            resourceAudiences = requestedResources.isEmpty() ? authorizedAudiences
                    : resourceIndicators.audiencesFor(requestedResources);
            if (!authorizedAudiences.containsAll(resourceAudiences)) {
                throw ResourceIndicators.invalidTarget("The requested resource was not authorized");
            }
        }

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

}
