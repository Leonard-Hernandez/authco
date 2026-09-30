package authco.security;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import authco.user.FederatedProfile;
import authco.user.FederatedUserService;
import authco.user.UserEntity;
import authco.user.exception.UnverifiedEmailConflictException;

@Component
public class FederatedOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegate = new OidcUserService();
    private FederatedUserService federatedUserService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegate.loadUser(userRequest);

        FederatedProfile federatedProfile = new FederatedProfile(
                userRequest.getClientRegistration().getRegistrationId(), oidcUser.getSubject(), oidcUser.getEmail(),
                Boolean.TRUE.equals(oidcUser.getEmailVerified()), oidcUser.getFullName());

        try {
            UserEntity userEntity = federatedUserService.findOrCreate(federatedProfile);
            //Set<String> claims = new HashSet<String>(oidcUser.getClaims())

            Set<String> newClaims = new HashSet<>(claims).add(new HashSet<>())
        } catch (UnverifiedEmailConflictException e) {
            throw new OAuth2AuthenticationException(new OAuth2Error(e.getMessage()), e);
        }

    }
}
