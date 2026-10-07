package authco.admin;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import authco.jwk.exception.ActiveKeyRevocationException;
import authco.jwk.exception.JwkKeyNotFoundException;
import authco.user.exception.UnknownRoleException;
import authco.user.exception.UserNotFoundException;

// Scoped to the admin controllers so it never changes how the login pages fail.
@RestControllerAdvice(assignableTypes = { AdminUserController.class, AdminJwkController.class })
public class AdminExceptionHandler {

    @ExceptionHandler({ UserNotFoundException.class, JwkKeyNotFoundException.class })
    ProblemDetail notFound(RuntimeException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, e.getMessage());
    }

    @ExceptionHandler(UnknownRoleException.class)
    ProblemDetail badRequest(RuntimeException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler(ActiveKeyRevocationException.class)
    ProblemDetail conflict(RuntimeException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, e.getMessage());
    }

}
