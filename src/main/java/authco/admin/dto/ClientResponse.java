package authco.admin.dto;

import java.time.Instant;
import java.util.Set;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import authco.client.ClientType;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "A registered client. The secret is never returned after creation.")
public record ClientResponse(
        String clientId,
        String clientName,
        ClientType type,
        Set<String> redirectUris,
        Set<String> postLogoutRedirectUris,
        Set<String> scopes,
        boolean requireConsent,
        Instant clientIdIssuedAt) {

    public static ClientResponse from(RegisteredClient client) {
        ClientType type = client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)
                ? ClientType.PUBLIC
                : ClientType.CONFIDENTIAL;
        return new ClientResponse(client.getClientId(), client.getClientName(), type,
                client.getRedirectUris(), client.getPostLogoutRedirectUris(), client.getScopes(),
                client.getClientSettings().isRequireAuthorizationConsent(), client.getClientIdIssuedAt());
    }
}
