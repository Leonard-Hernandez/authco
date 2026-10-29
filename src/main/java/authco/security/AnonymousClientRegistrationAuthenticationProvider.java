package authco.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.util.StringUtils;

/**
 * OIDC Dynamic Client Registration ({@code /connect/register}) without an initial
 * access token, restricted by {@link DynamicClientRegistrationPolicy}.
 *
 * <p>
 * The stock OIDC converter has no notion of public clients: it maps
 * {@code token_endpoint_auth_method=none} to {@code client_secret_basic} and makes up a
 * secret. MCP clients such as Claude.ai register as public clients (PKCE only), so
 * {@code none} is honored here and such clients are stored without a secret.
 * Confidential clients still get a generated secret, stored hashed and returned in
 * plain text only in this response.
 */
public class AnonymousClientRegistrationAuthenticationProvider implements AuthenticationProvider {

	private final RegisteredClientRepository registeredClientRepository;
	private final PasswordEncoder passwordEncoder;
	private final DynamicClientRegistrationPolicy registrationPolicy;

	private final Converter<OidcClientRegistration, RegisteredClient> registeredClientConverter = new OidcClientRegistrationRegisteredClientConverter();
	private final Converter<RegisteredClient, OidcClientRegistration> clientRegistrationConverter = new RegisteredClientOidcClientRegistrationConverter();

	public AnonymousClientRegistrationAuthenticationProvider(
			RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder,
			DynamicClientRegistrationPolicy registrationPolicy) {
		this.registeredClientRepository = registeredClientRepository;
		this.passwordEncoder = passwordEncoder;
		this.registrationPolicy = registrationPolicy;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = (OidcClientRegistrationAuthenticationToken) authentication;

		OidcClientRegistration oidcClientRegistration = clientRegistrationAuthentication.getClientRegistration();

		registrationPolicy.validateRedirectUris(oidcClientRegistration.getRedirectUris());
		registrationPolicy.validatePostLogoutRedirectUris(oidcClientRegistration.getPostLogoutRedirectUris());

		RegisteredClient registeredClient = registeredClientConverter.convert(oidcClientRegistration);
		if (ClientAuthenticationMethod.NONE.getValue()
				.equals(oidcClientRegistration.getTokenEndpointAuthenticationMethod())) {
			registeredClient = asPublicClient(registeredClient);
		}
		registeredClient = registrationPolicy.apply(registeredClient);

		// Public clients and private_key_jwt clients have no secret to hash.
		RegisteredClient storedClient = StringUtils.hasText(registeredClient.getClientSecret())
				? RegisteredClient.from(registeredClient)
						.clientSecret(passwordEncoder.encode(registeredClient.getClientSecret()))
						.build()
				: registeredClient;

		registeredClientRepository.save(storedClient);

		OidcClientRegistration oidcClientRegistrationPlainSecret = clientRegistrationConverter
				.convert(registeredClient);

		return new OidcClientRegistrationAuthenticationToken(authentication, oidcClientRegistrationPlainSecret);
	}

	/**
	 * Turns a client into a public one: no secret, authenticated at the token endpoint
	 * only by its PKCE code verifier.
	 */
	private static RegisteredClient asPublicClient(RegisteredClient registeredClient) {
		return RegisteredClient.from(registeredClient)
				.clientSecret(null)
				.clientAuthenticationMethods(methods -> {
					methods.clear();
					methods.add(ClientAuthenticationMethod.NONE);
				})
				.build();
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
