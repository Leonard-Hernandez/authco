package authco.user.exception;

import java.util.Set;

public class UnknownRoleException extends RuntimeException {

    public UnknownRoleException(Set<String> roles) {
        super("Unknown roles: " + String.join(", ", roles));
    }

}
