package authco.jwk.exception;

public class JwkKeyNotFoundException extends RuntimeException {

    public JwkKeyNotFoundException(String keyId) {
        super("Signing key not found: " + keyId);
    }

}
