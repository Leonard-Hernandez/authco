package authco.security;

import java.time.Duration;

/** Token lifetimes shared by every client authco registers (admin, DCR, demo). */
public final class TokenLifetimes {

	public static final Duration ACCESS_TOKEN = Duration.ofMinutes(15);
	public static final Duration REFRESH_TOKEN = Duration.ofDays(1);

	private TokenLifetimes() {
	}

}
