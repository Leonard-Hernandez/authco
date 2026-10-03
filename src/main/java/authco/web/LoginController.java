package authco.web;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("providers", providers());
        return "login";
    }

    // The repository interface only looks up by id; the in-memory one Boot builds
    // from application.yml is also Iterable, which is what lets us list them.
    private List<ClientRegistration> providers() {
        List<ClientRegistration> providers = new ArrayList<>();
        if (clientRegistrationRepository instanceof Iterable<?> registrations) {
            registrations.forEach(registration -> providers.add((ClientRegistration) registration));
        }
        return providers;
    }

}
