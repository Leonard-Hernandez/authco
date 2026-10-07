package authco.security;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import authco.user.FederatedProfile;
import authco.user.FederatedUserService;
import authco.user.UserEntity;
import authco.user.exception.UnverifiedEmailException;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class FederatedOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegate = new OidcUserService();
    private final FederatedUserService federatedUserService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegate.loadUser(userRequest);

        FederatedProfile federatedProfile = new FederatedProfile(
                userRequest.getClientRegistration().getRegistrationId(), oidcUser.getSubject(), oidcUser.getEmail(),
                Boolean.TRUE.equals(oidcUser.getEmailVerified()), oidcUser.getFullName());

        try {
            UserEntity userEntity = federatedUserService.findOrCreate(federatedProfile);
            Map<String, Object> claims = new HashMap<>(oidcUser.getClaims());

            claims.put("authco_id", userEntity.getId().toString());

            // The OIDC login provider (unlike the plain OAuth2 one) doesn't add the factor
            // authority, and JwtGenerator reads auth_time for the ID token from it.
            Set<GrantedAuthority> authorities = new HashSet<>(oidcUser.getAuthorities());
            authorities.add(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY));

            return new DefaultOidcUser(authorities, oidcUser.getIdToken(), new OidcUserInfo(claims), "authco_id");

        } catch (UnverifiedEmailException e) {
            throw new OAuth2AuthenticationException(new OAuth2Error("unverified_email", e.getMessage(), null), e);
        }

    }
}
