package authco.user.exception;

public class UnverifiedEmailConflictException extends IllegalStateException {

    public UnverifiedEmailConflictException() {
        super("Email is not verified");
    }

}
