package authco.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;

public class AnonymousClientRegistrationAuthenticationProvider implements AuthenticationProvider {

	private final RegisteredClientRepository registeredClientRepository;
	private final PasswordEncoder passwordEncoder;

	private final Converter<OidcClientRegistration, RegisteredClient> registeredClientConverter = new OidcClientRegistrationRegisteredClientConverter();
	private final Converter<RegisteredClient, OidcClientRegistration> clientRegistrationConverter = new RegisteredClientOidcClientRegistrationConverter();

	public AnonymousClientRegistrationAuthenticationProvider(
			RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder) {
		this.registeredClientRepository = registeredClientRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = (OidcClientRegistrationAuthenticationToken) authentication;


		OidcClientRegistration oidcClientRegistration = clientRegistrationAuthentication.getClientRegistration();

		RegisteredClient registeredClient = registeredClientConverter.convert(oidcClientRegistration);


		RegisteredClient registeredClientEncode = RegisteredClient.from(registeredClient)
				.clientSecret(passwordEncoder.encode(registeredClient.getClientSecret()))
				.build();

		registeredClientRepository.save(registeredClientEncode);

		OidcClientRegistration oidcClientRegistrationPlainScrect = clientRegistrationConverter.convert(registeredClient);

		return new OidcClientRegistrationAuthenticationToken(authentication, oidcClientRegistrationPlainScrect);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
