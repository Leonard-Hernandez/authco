package authco.web;

import java.net.URI;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import authco.user.UserEntity;
import authco.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

// Only renders the page. The decision is posted back to /oauth2/authorize,
// where the authorization server validates and stores the consent.
@Controller
@RequiredArgsConstructor
public class ConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final UserRepository userRepository;

    @GetMapping("/oauth2/consent")
    public String consent(Principal principal, Model model,
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
            @RequestParam(OAuth2ParameterNames.STATE) String state) {

        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new IllegalArgumentException("Unknown client: " + clientId);
        }

        // openid is approved by the server along with any other scope; it never needs consent.
        List<String> scopes = Arrays.stream(scope.split(" "))
                .filter(s -> !s.isBlank() && !OidcScopes.OPENID.equals(s))
                .toList();

        // The principal name is the authco user id, so the email comes from our own records.
        String userEmail = userRepository.findById(principal.getName())
                .map(UserEntity::getEmail)
                .orElseThrow();

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", client.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopes);
        model.addAttribute("userEmail", userEmail);
        model.addAttribute("redirectHost", redirectHost(client.getRedirectUris()));

        return "consent";
    }

    // Only shown when the destination is unambiguous: a client with several
    // redirect URIs could send the user to any of them.
    private String redirectHost(Set<String> redirectUris) {
        if (redirectUris.size() != 1) {
            return null;
        }
        return URI.create(redirectUris.iterator().next()).getHost();
    }

}
