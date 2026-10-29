package authco.config;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Issuers authco answers as ({@code authco.issuer}, comma-separated).
 *
 * <p>
 * One issuer (the usual case): pinned, so iss and every URL in the discovery documents
 * never depend on the Host header of whoever asks.
 *
 * <p>
 * Several issuers: one authco shared by apps on different origins (e.g. restauco and
 * barberco, each behind its own gateway). Each request gets the issuer of the origin it
 * came through, so every SPA logs in on its own origin and its API validates its own
 * iss. The list is closed: a request through any other origin (in-cluster calls such
 * as http://authco:8087 for JWKS or userinfo, or a forged Host) is served as the first
 * issuer, never as the origin it claims.
 */
@Configuration
public class IssuerConfig {

	@Bean
	AuthorizationServerSettings authorizationServerSettings(@Value("${authco.issuer}") List<String> issuers) {
		AuthorizationServerSettings.Builder settings = AuthorizationServerSettings.builder();
		// Without an issuer, SAS resolves it per request (origin + context path), which
		// IssuerAllowlistFilter has already narrowed to an allowed one.
		return (issuers.size() == 1 ? settings.issuer(issuers.getFirst()) : settings).build();
	}

	// Right after the ForwardedHeaderFilter (HIGHEST_PRECEDENCE), so the origin checked
	// is the public one from X-Forwarded-*, and before the security filter chains.
	@Bean
	FilterRegistrationBean<IssuerAllowlistFilter> issuerAllowlistFilter(
			@Value("${authco.issuer}") List<String> issuers) {
		FilterRegistrationBean<IssuerAllowlistFilter> registration = new FilterRegistrationBean<>(
				new IssuerAllowlistFilter(issuers));
		registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
		return registration;
	}

	static final class IssuerAllowlistFilter extends OncePerRequestFilter {

		private final List<String> issuers;

		IssuerAllowlistFilter(List<String> issuers) {
			this.issuers = issuers.stream().map(IssuerAllowlistFilter::withoutTrailingSlash).toList();
		}

		@Override
		protected boolean shouldNotFilter(HttpServletRequest request) {
			return issuers.size() == 1;
		}

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain chain) throws ServletException, IOException {
			if (issuers.contains(issuerOf(request))) {
				chain.doFilter(request, response);
			} else {
				chain.doFilter(new AsOrigin(request, URI.create(issuers.getFirst())), response);
			}
		}

		// Same resolution as SAS: the request's origin plus the context path (/authco).
		static String issuerOf(HttpServletRequest request) {
			return UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
					.replacePath(request.getContextPath()).replaceQuery(null).fragment(null).build().toUriString();
		}

		private static String withoutTrailingSlash(String issuer) {
			return issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
		}

	}

	/** The request as if it had arrived through the given issuer's origin. */
	static final class AsOrigin extends HttpServletRequestWrapper {

		private final URI origin;

		AsOrigin(HttpServletRequest request, URI origin) {
			super(request);
			this.origin = origin;
		}

		@Override
		public String getScheme() {
			return origin.getScheme();
		}

		@Override
		public boolean isSecure() {
			return "https".equals(origin.getScheme());
		}

		@Override
		public String getServerName() {
			return origin.getHost();
		}

		@Override
		public int getServerPort() {
			if (origin.getPort() != -1) {
				return origin.getPort();
			}
			return isSecure() ? 443 : 80;
		}

		@Override
		public StringBuffer getRequestURL() {
			StringBuffer url = new StringBuffer(getScheme()).append("://").append(getServerName());
			if (origin.getPort() != -1) {
				url.append(':').append(origin.getPort());
			}
			return url.append(getRequestURI());
		}

	}

}
