package authco.client;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/** The stored client plus its clear secret, which exists only in this response. */
public record CreatedClient(RegisteredClient client, String clientSecret) {
}
