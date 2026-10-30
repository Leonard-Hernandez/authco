package authco.client;

import java.util.LinkedHashSet;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import authco.client.exception.ClientAlreadyExistsException;
import authco.security.ClientScopes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Seeds the first-party SPA (e.g. finco-site) as a public client on startup, so a
 * fresh deployment can log in without a call to the admin API.
 *
 * <p>
 * Disabled while {@code authco.spa-client.client-id} is empty. Only creates the client
 * when it does not exist yet, also when several replicas start at once; afterwards the
 * admin API owns it. Public, PKCE required,
 * no consent (first-party) and no refresh tokens. Role scopes (finco:admin...) are not
 * registered on the client: they come from the user's roles at token time.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SpaClientInitializer implements ApplicationRunner {

    static final String CLIENT_NAME = "First-party SPA";

    private final ClientAdminService clientAdminService;
    private final RegisteredClientRepository registeredClientRepository;

    @Value("${authco.spa-client.client-id}")
    private String clientId;

    @Value("${authco.spa-client.redirect-uris}")
    private List<String> redirectUris;

    @Value("${authco.spa-client.post-logout-redirect-uris}")
    private List<String> postLogoutRedirectUris;

    @Override
    public void run(ApplicationArguments args) {
        if (clientId.isBlank() || registeredClientRepository.findByClientId(clientId) != null) {
            return;
        }

        try {
            clientAdminService.create(new ClientDefinition(clientId, CLIENT_NAME, ClientType.PUBLIC,
                    new LinkedHashSet<>(redirectUris), new LinkedHashSet<>(postLogoutRedirectUris),
                    ClientScopes.ALLOWED, false));
        } catch (ClientAlreadyExistsException | DataIntegrityViolationException | IllegalArgumentException ex) {
            // Replicas starting together race between the check above and the insert:
            // the loser sees the winner's client (ClientAlreadyExistsException), Spring
            // Authorization Server's own uniqueness check (IllegalArgumentException) or
            // the unique constraint on client_id. Anything else is a real failure.
            if (registeredClientRepository.findByClientId(clientId) == null) {
                throw ex;
            }
            log.info("SPA client '{}' already seeded by another instance", clientId);
            return;
        }
        log.info("Seeded SPA client '{}' (redirect URIs: {})", clientId, redirectUris);
    }

}
