package authco.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import authco.jwk.JwkKeyService;
import authco.security.AnonymousClientRegistrationAuthenticationProvider;
import authco.security.FederatedOidcUserService;
import lombok.AllArgsConstructor;

@Configuration
@AllArgsConstructor
public class AuthorizationServerConfig {

	private final FederatedOidcUserService federatedOidcUserService;

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder) throws Exception {

		http.oauth2AuthorizationServer((authorizationServer) -> {
			authorizationServer
					.authorizationEndpoint(endpoint -> endpoint.consentPage("/oauth2/consent"))
					.oidc(oidc -> oidc.clientRegistrationEndpoint(reg -> reg.authenticationProviders(providers -> {
						providers.clear();
						providers.add(new AnonymousClientRegistrationAuthenticationProvider(registeredClientRepository,
								passwordEncoder));
					})));
			http.securityMatcher(authorizationServer.getEndpointsMatcher());
		})
				.authorizeHttpRequests((autorize) -> autorize
						.requestMatchers("/connect/register").permitAll()
						.anyRequest().authenticated())

				.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {

		// /error must stay open: a 401 from another chain (e.g. the admin Basic auth) is
		// forwarded there, and requiring login on it turns the 401 into a redirect to /login.
		return http.authorizeHttpRequests((autorize) -> autorize
				.requestMatchers("/error").permitAll()
				.anyRequest().authenticated())
				.oauth2Login(
						oauth -> oauth.loginPage("/login").permitAll()
								.userInfoEndpoint(userinfo -> userinfo.oidcUserService(federatedOidcUserService)))
				.build();

	}

	@Bean
	RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

		if (repository.findByClientId("oidc-client") == null) {
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
					.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15))
							.refreshTokenTimeToLive(Duration.ofDays(1)).build())
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

	// After a rotation the JWKS holds several RS256 keys, and NimbusJwtEncoder refuses
	// to guess which one to sign with. Retired keys are there only for verification.
	@Bean
	JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource, JwkKeyService jwkKeyService) {
		NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
		encoder.setJwkSelector(jwks -> {
			String activeKeyId = jwkKeyService.getActiveKeyId();
			return jwks.stream()
					.filter(jwk -> activeKeyId.equals(jwk.getKeyID()))
					.findFirst()
					.orElseThrow(() -> new IllegalStateException("Active signing key " + activeKeyId + " is not in the JWKS"));
		});
		return encoder;
	}

	@Bean
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(BCryptVersion.$2Y);
	}

}
