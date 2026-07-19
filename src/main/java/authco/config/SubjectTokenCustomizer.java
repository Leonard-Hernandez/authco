package authco.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import authco.user.repository.FederatedIdentityRepository;
import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class SubjectTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final FederatedIdentityRepository federatedIdentityRepository;

    @Override
    public void customize(JwtEncodingContext context) {

        Authentication principal = context.getPrincipal();

        if (principal.getPrincipal() instanceof OAuth2User oAuth2User) {

            String provider = ((OAuth2AuthenticationToken) principal)
                    .getAuthorizedClientRegistrationId();
            String providerUserId = oAuth2User.getName();

            String authcoUuid = federatedIdentityRepository
                    .findByProviderAndProviderUserId(provider, providerUserId)
                    .map(federate -> federate.getUser().getId())
                    .orElseThrow();

            context.getClaims().subject(authcoUuid);
            
        }
        
    }

}
