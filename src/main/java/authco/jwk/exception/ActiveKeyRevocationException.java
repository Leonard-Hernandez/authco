package authco.jwk.exception;

public class ActiveKeyRevocationException extends RuntimeException {

    public ActiveKeyRevocationException(String keyId) {
        super("Key " + keyId + " is the active signing key; rotate before revoking it");
    }

}
