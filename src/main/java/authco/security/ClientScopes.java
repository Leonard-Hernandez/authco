package authco.security;

import java.util.Set;

import org.springframework.security.oauth2.core.oidc.OidcScopes;

public final class ClientScopes {

	public static final Set<String> ALLOWED = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL);

	private ClientScopes() {
	}

}
