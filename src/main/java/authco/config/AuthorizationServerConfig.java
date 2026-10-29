package authco.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import authco.jwk.JwkKeyService;
import authco.security.AnonymousClientRegistrationAuthenticationProvider;
import authco.security.DynamicClientRegistrationPolicy;
import authco.security.FederatedOidcUserService;
import authco.security.TokenLifetimes;
import lombok.AllArgsConstructor;

@Configuration
@AllArgsConstructor
public class AuthorizationServerConfig {

	// SAS runs the authorization endpoint after AuthorizationFilter, so without this an
	// anonymous prompt=none request is sent to /login instead of getting SAS's
	// error=login_required on the client's redirect URI. Sessions still apply: with
	// one, the code is issued as usual.
	private static final RequestMatcher SILENT_AUTHORIZATION_REQUEST = new AndRequestMatcher(
			PathPatternRequestMatcher.pathPattern("/oauth2/authorize"),
			request -> "none".equals(request.getParameter("prompt")));

	private final FederatedOidcUserService federatedOidcUserService;

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			CorsConfigurationSource corsConfigurationSource,
			RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder,
			DynamicClientRegistrationPolicy registrationPolicy,
			@Value("${authco.cors.allowed-origins}") List<String> allowedOrigins) throws Exception {

		http.oauth2AuthorizationServer((authorizationServer) -> {
			authorizationServer
					.authorizationEndpoint(endpoint -> endpoint.consentPage("/oauth2/consent"))
					// RFC 7591 registration (/oauth2/register), advertised in
					// /.well-known/oauth-authorization-server: what MCP clients look for.
					.clientRegistrationEndpoint(reg -> reg
							.openRegistrationAllowed(true)
							.authenticationProviders(providers -> providers.forEach(provider -> {
								if (provider instanceof OAuth2ClientRegistrationAuthenticationProvider registration) {
									applyRegistrationPolicy(registration, registrationPolicy);
								}
							})))
					// OIDC registration (/connect/register), advertised in
					// /.well-known/openid-configuration.
					.oidc(oidc -> oidc.clientRegistrationEndpoint(reg -> reg.authenticationProviders(providers -> {
						providers.clear();
						providers.add(new AnonymousClientRegistrationAuthenticationProvider(registeredClientRepository,
								passwordEncoder, registrationPolicy));
					})));
			http.securityMatcher(authorizationServer.getEndpointsMatcher());
		})
				.authorizeHttpRequests((autorize) -> autorize
						.requestMatchers("/connect/register", "/oauth2/register").permitAll()
						.requestMatchers(SILENT_AUTHORIZATION_REQUEST).permitAll()
						.anyRequest().authenticated())

				.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
				.cors(cors -> cors.configurationSource(
						corsConfigurationSource))
				.headers(headers -> allowFramingBy(headers, allowedOrigins));
		return http.build();
	}

	/**
	 * Same anonymous policy as {@link AnonymousClientRegistrationAuthenticationProvider}.
	 * The stock RFC 7591 converter already handles public clients
	 * ({@code token_endpoint_auth_method=none}) and the provider only hashes secrets
	 * that exist. Requested scopes are narrowed by the policy instead of rejected, as on
	 * the OIDC endpoint.
	 */
	private static void applyRegistrationPolicy(OAuth2ClientRegistrationAuthenticationProvider provider,
			DynamicClientRegistrationPolicy registrationPolicy) {
		provider.setAuthenticationValidator(OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
				.andThen(OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR)
				.andThen(OAuth2ClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR)
				.andThen(context -> {
					OAuth2ClientRegistrationAuthenticationToken registration = context.getAuthentication();
					registrationPolicy.validateRedirectUris(registration.getClientRegistration().getRedirectUris());
					// Not RFC 7591 metadata (the stock converter drops it), but rejected rather
					// than ignored if sent with a URI outside the allowlist.
					registrationPolicy.validatePostLogoutRedirectUris(registration.getClientRegistration()
							.getClaimAsStringList(DynamicClientRegistrationPolicy.POST_LOGOUT_REDIRECT_URIS));
				}));

		OAuth2ClientRegistrationRegisteredClientConverter converter = new OAuth2ClientRegistrationRegisteredClientConverter();
		provider.setRegisteredClientConverter(
				clientRegistration -> registrationPolicy.apply(converter.convert(clientRegistration)));
	}

	@Bean
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
			@Value("${authco.cors.allowed-origins}") List<String> allowedOrigins) {

		// /error must stay open: a 401 from another chain (e.g. the admin Basic auth)
		// is forwarded there, and requiring login on it turns the 401 into a redirect
		// to
		// /login.
		// Health probes are unauthenticated (show-details is never, so they only expose
		// UP/DOWN). They must be listed before anyRequest().
		return http.authorizeHttpRequests((autorize) -> autorize
				.requestMatchers("/error", "/actuator/health", "/actuator/health/**").permitAll()
				.anyRequest().authenticated())
				.oauth2Login(
						oauth -> oauth.loginPage("/login").permitAll()
								.userInfoEndpoint(userinfo -> userinfo.oidcUserService(federatedOidcUserService)))
				.headers(headers -> allowFramingBy(headers, allowedOrigins))
				.build();

	}

	/**
	 * Silent authentication: the SPA renews its tokens in a hidden iframe pointed at
	 * /oauth2/authorize?prompt=none, which the default X-Frame-Options: DENY would block.
	 * Framing is allowed only for this server and the CORS origins (the SPAs), through
	 * CSP frame-ancestors, which supersedes X-Frame-Options and supports an allowlist.
	 * Covers both chains, since the iframe may land on /login when there is no session.
	 */
	private static void allowFramingBy(HeadersConfigurer<HttpSecurity> headers, List<String> allowedOrigins) {
		headers.frameOptions(frameOptions -> frameOptions.disable())
				.contentSecurityPolicy(csp -> csp
						.policyDirectives(("frame-ancestors 'self' " + String.join(" ", allowedOrigins)).trim()));
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource(
			@Value("${authco.cors.allowed-origins}") List<String> allowSites) {
		CorsConfiguration corsConfiguration = new CorsConfiguration();
		corsConfiguration.setAllowedOrigins(allowSites);
		corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "OPTIONS"));
		corsConfiguration.setAllowCredentials(false);
		corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
		corsConfiguration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfiguration);

		return source;

	}

	@Bean
	RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate,
			@Value("${authco.seed-demo-client}") boolean seedDemoClient) {
		JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

		// Local demo client only (well-known secret, loopback redirect): never seeded
		// unless explicitly enabled.
		if (seedDemoClient && repository.findByClientId("oidc-client") == null) {
			RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
					.clientId("oidc-client")
					.clientSecret("{noop}secret")
					.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
					.redirectUri("http://127.0.0.1:8888/callback")
					.postLogoutRedirectUri("http://127.0.0.1:8888/")
					.scope(OidcScopes.OPENID)
					.scope(OidcScopes.PROFILE)
					.scope(OidcScopes.EMAIL)
					.clientSettings(ClientSettings.builder()
							.requireProofKey(true)
							.requireAuthorizationConsent(true)
							.build())
					.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(TokenLifetimes.ACCESS_TOKEN)
							.refreshTokenTimeToLive(TokenLifetimes.REFRESH_TOKEN).build())
					.build();

			repository.save(oidcClient);

		}

		return repository;

	}

	@Bean
	OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	JWKSource<SecurityContext> jwkSource(JwkKeyService jwkKeyService) {
		return (jwkSelector, secutityContext) -> {

			List<JWK> jwks = new ArrayList<>(jwkKeyService.getAllKeys());
			return jwkSelector.select(new JWKSet(jwks));

		};

	}

	// After a rotation the JWKS holds several RS256 keys, and NimbusJwtEncoder
	// refuses
	// to guess which one to sign with. Retired keys are there only for
	// verification.
	@Bean
	JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource, JwkKeyService jwkKeyService) {
		NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
		encoder.setJwkSelector(jwks -> {
			String activeKeyId = jwkKeyService.getActiveKeyId();
			return jwks.stream()
					.filter(jwk -> activeKeyId.equals(jwk.getKeyID()))
					.findFirst()
					.orElseThrow(() -> new IllegalStateException(
							"Active signing key " + activeKeyId + " is not in the JWKS"));
		});
		return encoder;
	}

	@Bean
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(BCryptVersion.$2Y);
	}

}
