package authco.client;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import authco.client.exception.ClientAlreadyExistsException;
import authco.client.exception.ClientNotFoundException;
import authco.client.exception.InvalidClientException;
import authco.security.ClientScopes;
import lombok.RequiredArgsConstructor;

/**
 * Trusted clients registered by an admin. Unlike Dynamic Client Registration, the
 * admin decides the redirect URIs and the consent policy, so first-party apps can
 * skip the consent screen. Policy that is not negotiable (PKCE, the authorization
 * code grant, token lifetimes) is fixed here rather than exposed in the API.
 */
@Service
@RequiredArgsConstructor
public class ClientAdminService {

    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(15);
    private static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(1);
    private static final int SECRET_BYTES = 32;
    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");

    private final RegisteredClientRepository registeredClientRepository;
    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;

    // RegisteredClientRepository has no "find all"; the table is the source of truth.
    public List<RegisteredClient> list() {
        return jdbcTemplate.queryForList(
                "SELECT client_id FROM oauth2_registered_client ORDER BY client_id_issued_at DESC", String.class)
                .stream()
                .map(registeredClientRepository::findByClientId)
                .filter(Objects::nonNull)
                .toList();
    }

    public RegisteredClient get(String clientId) {
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new ClientNotFoundException(clientId);
        }
        return client;
    }

    @Transactional
    public CreatedClient create(ClientDefinition definition) {
        if (registeredClientRepository.findByClientId(definition.clientId()) != null) {
            throw new ClientAlreadyExistsException(definition.clientId());
        }
        validate(definition.redirectUris(), definition.postLogoutRedirectUris(), definition.scopes());

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(definition.clientId())
                .clientIdIssuedAt(Instant.now())
                .clientName(definition.clientName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUris(uris -> uris.addAll(definition.redirectUris()))
                .postLogoutRedirectUris(uris -> uris.addAll(definition.postLogoutRedirectUris()))
                .scopes(scopes -> scopes.addAll(definition.scopes()))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(definition.requireConsent())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(ACCESS_TOKEN_TTL)
                        .refreshTokenTimeToLive(REFRESH_TOKEN_TTL)
                        .build());

        String clearSecret = null;
        if (definition.type() == ClientType.CONFIDENTIAL) {
            clearSecret = generateSecret();
            builder.clientSecret(passwordEncoder.encode(clearSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    // Only confidential clients receive refresh tokens; Spring never
                    // issues them to public ones, so declaring it there would mislead.
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }

        RegisteredClient client = builder.build();
        registeredClientRepository.save(client);
        return new CreatedClient(client, clearSecret);
    }

    @Transactional
    public RegisteredClient update(String clientId, String clientName, Set<String> redirectUris,
            Set<String> postLogoutRedirectUris, Set<String> scopes, boolean requireConsent) {
        RegisteredClient existing = get(clientId);
        validate(redirectUris, postLogoutRedirectUris, scopes);

        RegisteredClient updated = RegisteredClient.from(existing)
                .clientName(clientName)
                .redirectUris(uris -> {
                    uris.clear();
                    uris.addAll(redirectUris);
                })
                .postLogoutRedirectUris(uris -> {
                    uris.clear();
                    uris.addAll(postLogoutRedirectUris);
                })
                .scopes(s -> {
                    s.clear();
                    s.addAll(scopes);
                })
                .clientSettings(ClientSettings.withSettings(existing.getClientSettings().getSettings())
                        .requireAuthorizationConsent(requireConsent)
                        .build())
                .build();

        registeredClientRepository.save(updated);
        return updated;
    }

    // Removes the client and everything issued to it. JWT access tokens already
    // handed out stay valid until they expire: they are verified without a lookup.
    @Transactional
    public void delete(String clientId) {
        String registeredClientId = get(clientId).getId();
        jdbcTemplate.update("DELETE FROM oauth2_authorization WHERE registered_client_id = ?", registeredClientId);
        jdbcTemplate.update("DELETE FROM oauth2_authorization_consent WHERE registered_client_id = ?",
                registeredClientId);
        jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE id = ?", registeredClientId);
    }

    private void validate(Set<String> redirectUris, Set<String> postLogoutRedirectUris, Set<String> scopes) {
        if (redirectUris.isEmpty()) {
            throw new InvalidClientException("At least one redirect URI is required");
        }
        redirectUris.forEach(ClientAdminService::validateUri);
        postLogoutRedirectUris.forEach(ClientAdminService::validateUri);

        // Role scopes (finco:premium...) come from the user's roles, never from the client.
        Set<String> notAllowed = new HashSet<>(scopes);
        notAllowed.removeAll(ClientScopes.ALLOWED);
        if (!notAllowed.isEmpty()) {
            throw new InvalidClientException("Scopes not allowed for clients: " + String.join(", ", notAllowed)
                    + ". Allowed: " + String.join(", ", ClientScopes.ALLOWED));
        }
    }

    // Absolute, exact URIs only. Plain http is accepted for local development hosts;
    // anywhere else the authorization code would travel unencrypted.
    private static void validateUri(String value) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidClientException("Not a valid URI: " + value);
        }
        if (uri.getHost() == null || uri.getScheme() == null) {
            throw new InvalidClientException("Redirect URIs must be absolute: " + value);
        }
        if (uri.getFragment() != null) {
            throw new InvalidClientException("Redirect URIs cannot contain a fragment: " + value);
        }
        boolean https = "https".equals(uri.getScheme());
        boolean localHttp = "http".equals(uri.getScheme()) && LOCAL_HOSTS.contains(uri.getHost());
        if (!https && !localHttp) {
            throw new InvalidClientException("Redirect URIs must use https (http only for localhost): " + value);
        }
    }

    private static String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
