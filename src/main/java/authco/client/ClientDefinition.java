package authco.client;

import java.util.Set;

/** What an admin decides about a client; everything else is fixed policy. */
public record ClientDefinition(
        String clientId,
        String clientName,
        ClientType type,
        Set<String> redirectUris,
        Set<String> postLogoutRedirectUris,
        Set<String> scopes,
        boolean requireConsent) {
}
