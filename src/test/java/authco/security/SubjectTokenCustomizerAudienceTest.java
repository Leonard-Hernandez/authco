package authco.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import authco.config.Issuers;
import authco.user.UserEntity;
import authco.user.repository.UserRepository;

/**
 * RFC 8707: the access token audience follows the {@code resource} the client asked
 * for, within what was authorized at the authorization endpoint, falls back to the
 * first configured resource, and always keeps the client_id.
 */
class SubjectTokenCustomizerAudienceTest {

    private static final String USER_ID = "0e4d7594-2f25-4080-8d98-5abf1cce43e1";
    private static final String FINCO = "http://finco.localhost/finco-api/v1";
    private static final String OTHER = "http://other.localhost/api";
    private static final String CALLBACK = "https://claude.ai/api/mcp/auth_callback";

    private final RegisteredClient client = RegisteredClient.withId("id")
            .clientId("claude-client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(CALLBACK)
            .scope("openid")
            .build();

    private SubjectTokenCustomizer customizer;

    @BeforeEach
    void setUp() {
        UserEntity user = new UserEntity();
        user.setId(USER_ID);
        user.setEmail("user@example.com");

        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(userRepository.findRoleNamesByUserId(USER_ID)).thenReturn(Set.of());

        customizer = new SubjectTokenCustomizer(userRepository, new ResourceIndicators(List.of(FINCO, OTHER)),
                new Issuers(List.of("http://localhost:8087/authco")));
    }

    private final OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(client,
            ClientAuthenticationMethod.NONE, null);

    private JwtEncodingContext accessTokenContext(Map<String, Object> tokenRequestParameters,
            OAuth2Authorization authorization) {
        return accessTokenContext(new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, CALLBACK,
                tokenRequestParameters), authorization);
    }

    private JwtEncodingContext accessTokenContext(OAuth2AuthorizationGrantAuthenticationToken grant,
            OAuth2Authorization authorization) {
        DefaultOAuth2User user = new DefaultOAuth2User(AuthorityUtils.NO_AUTHORITIES, Map.of("sub", USER_ID), "sub");

        JwtEncodingContext.Builder builder = JwtEncodingContext
                .with(JwsHeader.with(SignatureAlgorithm.RS256),
                        JwtClaimsSet.builder().audience(List.of(client.getClientId())))
                .registeredClient(client)
                .principal(new TestingAuthenticationToken(user, null))
                .authorizedScopes(Set.of("openid"))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(grant.getGrantType())
                .authorizationGrant(grant);
        if (authorization != null) {
            builder.authorization(authorization);
        }
        return builder.build();
    }

    private static List<String> audience(JwtEncodingContext context) {
        return context.getClaims().build().getAudience();
    }

    @Test
    @DisplayName("an MCP endpoint below an allowlisted resource yields the canonical resource URI")
    void resourceBelowAllowlistedUri() {
        JwtEncodingContext context = accessTokenContext(Map.of("resource", FINCO + "/mcp"), null);

        customizer.customize(context);

        assertEquals(List.of("claude-client", FINCO), audience(context));
    }

    @Test
    @DisplayName("the exact resource (trailing slash ignored) is accepted")
    void exactResource() {
        JwtEncodingContext context = accessTokenContext(Map.of("resource", FINCO + "/"), null);

        customizer.customize(context);

        assertEquals(List.of("claude-client", FINCO), audience(context));
    }

    @Test
    @DisplayName("without a resource the first configured resource is the audience")
    void defaultAudience() {
        JwtEncodingContext context = accessTokenContext(Map.of(), null);

        customizer.customize(context);

        assertEquals(List.of("claude-client", FINCO), audience(context));
    }

    /** An authorization whose /oauth2/authorize request carried these resources. */
    private OAuth2Authorization authorizedFor(String... resources) {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("http://localhost:8087/authco/oauth2/authorize")
                .clientId(client.getClientId())
                .redirectUri(CALLBACK)
                .additionalParameters(Map.of("resource", List.of(resources)))
                .build();
        return OAuth2Authorization.withRegisteredClient(client)
                .principalName(USER_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .build();
    }

    private OAuth2RefreshTokenAuthenticationToken refresh(Map<String, Object> parameters) {
        return new OAuth2RefreshTokenAuthenticationToken("refresh-token", clientPrincipal, null, parameters);
    }

    @Test
    @DisplayName("the resource sent to the authorization endpoint applies when the token request omits it")
    void resourceFromAuthorizationRequest() {
        JwtEncodingContext context = accessTokenContext(Map.of(), authorizedFor(FINCO + "/mcp"));

        customizer.customize(context);

        assertEquals(List.of("claude-client", FINCO), audience(context));
    }

    @Test
    @DisplayName("the code exchange cannot swap the authorized resource for another one")
    void codeExchangeCannotWidenResources() {
        JwtEncodingContext context = accessTokenContext(Map.of("resource", OTHER), authorizedFor(FINCO));

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class,
                () -> customizer.customize(context));
        assertEquals("invalid_target", ex.getError().getErrorCode());
    }

    @Test
    @DisplayName("the token request may narrow the authorized resources")
    void tokenRequestNarrowsResources() {
        JwtEncodingContext context = accessTokenContext(Map.of("resource", OTHER), authorizedFor(FINCO, OTHER));

        customizer.customize(context);

        assertEquals(List.of("claude-client", OTHER), audience(context));
    }

    @Test
    @DisplayName("a refresh stays within the resources authorized at the authorization endpoint")
    void refreshConstrainedToAuthorizedResources() {
        OAuth2Authorization authorization = authorizedFor(FINCO + "/mcp");

        JwtEncodingContext withoutResource = accessTokenContext(refresh(Map.of()), authorization);
        customizer.customize(withoutResource);
        assertEquals(List.of("claude-client", FINCO), audience(withoutResource));

        JwtEncodingContext otherResource = accessTokenContext(refresh(Map.of("resource", OTHER)), authorization);
        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class,
                () -> customizer.customize(otherResource));
        assertEquals("invalid_target", ex.getError().getErrorCode());
    }

    @Test
    @DisplayName("a resource that is not allowlisted is rejected with invalid_target")
    void unknownResourceRejected() {
        JwtEncodingContext context = accessTokenContext(Map.of("resource", "http://finco.localhost/finco-api/v1-admin"),
                null);

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class,
                () -> customizer.customize(context));
        assertEquals("invalid_target", ex.getError().getErrorCode());
    }

    @Test
    @DisplayName("the audience of ID tokens is left alone")
    void idTokenUntouched() {
        DefaultOAuth2User user = new DefaultOAuth2User(AuthorityUtils.NO_AUTHORITIES, Map.of("sub", USER_ID), "sub");
        JwtEncodingContext context = JwtEncodingContext
                .with(JwsHeader.with(SignatureAlgorithm.RS256),
                        JwtClaimsSet.builder().audience(List.of(client.getClientId())))
                .registeredClient(client)
                .principal(new TestingAuthenticationToken(user, null))
                .authorizedScopes(Set.of("openid"))
                .tokenType(new OAuth2TokenType("id_token"))
                .build();

        customizer.customize(context);

        assertEquals(List.of("claude-client"), audience(context));
        assertEquals(USER_ID, context.getClaims().build().getClaims().get(JwtClaimNames.SUB));
    }

}
