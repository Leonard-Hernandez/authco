package authco.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import authco.user.UserEntity;
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

            UserEntity user = federatedIdentityRepository
                    .findByProviderAndProviderUserId(provider, providerUserId)
                    .map(federate -> federate.getUser())
                    .orElseThrow();
            
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                if (context.getAuthorizedScopes().contains("email")) {
                    context.getClaims().claim("email", user.getEmail());
                }                
            }


            context.getClaims().subject(user.getId());
            
        }
        
    }

}
