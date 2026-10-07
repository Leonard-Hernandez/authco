package authco.user.exception;

public class UnverifiedEmailException extends IllegalStateException {

    public UnverifiedEmailException() {
        super("Email is not verified");
    }

}
