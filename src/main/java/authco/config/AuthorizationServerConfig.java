package authco.config;

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
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import authco.jwk.JwkKeyService;
import authco.security.FederatedLoginSuccessHandler;
import lombok.AllArgsConstructor;

@Configuration
@AllArgsConstructor
public class AuthorizationServerConfig {

	private final FederatedLoginSuccessHandler federatedLoginSuccessHandler;

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder) throws Exception {

		http.oauth2AuthorizationServer((authorizationServer) -> {
			authorizationServer
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

		return http.authorizeHttpRequests((autorize) -> autorize.anyRequest().authenticated())
				.formLogin(form -> form.loginPage("/login").permitAll())
				.oauth2Login(oauth -> oauth.loginPage("/login").successHandler(federatedLoginSuccessHandler))
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
					.clientSettings(ClientSettings.builder()
							.requireProofKey(true)
							.requireAuthorizationConsent(true)
							.build())
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
