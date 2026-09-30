package authco.user;

public record FederatedProfile(String provider, String providerUserId, String email, boolean emailVerified, String name) {

}
