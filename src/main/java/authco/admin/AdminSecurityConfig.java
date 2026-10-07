package authco.admin;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Admin API and its Swagger UI, behind HTTP Basic with the generated admin login.
 * Runs before the authorization server and login chains, and only for these paths.
 */
@Configuration
public class AdminSecurityConfig {

    static final String[] ADMIN_PATHS = { "/admin/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html" };

    @Bean
    @Order(0)
    SecurityFilterChain adminSecurityFilterChain(HttpSecurity http,
            AdminCredentialRepository adminCredentialRepository, PasswordEncoder passwordEncoder) {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(
                new AdminUserDetailsService(adminCredentialRepository));
        provider.setPasswordEncoder(passwordEncoder);

        return http.securityMatcher(ADMIN_PATHS)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("ADMIN"))
                .authenticationManager(new ProviderManager(provider))
                .httpBasic(Customizer.withDefaults())
                // Stateless: the credentials travel on every request, so there is no
                // session cookie for a cross-site request to ride on, hence no CSRF.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .build();
    }

}
