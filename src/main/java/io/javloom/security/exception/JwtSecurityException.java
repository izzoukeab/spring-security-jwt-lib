package io.javloom.security.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Runtime exception used for authentication and authorization failures.
 */
@Getter
public class JwtSecurityException extends RuntimeException {

    /** HTTP status returned for this authentication error. */
    private final HttpStatus status;

    /**
     * Creates a new JWT auth exception.
     *
     * @param status  HTTP status to expose
     * @param message error message
     */
    public JwtSecurityException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    /**
     * Creates a 401 Unauthorized exception.
     *
     * @param message error message
     * @return unauthorized auth exception
     */
    public static JwtSecurityException unauthorized() {
        return new JwtSecurityException(HttpStatus.UNAUTHORIZED, "User doesn't have permission to access this resource");
    }

    /**
     * Creates a 401 Unauthorized exception.
     *
     * @param message error message
     * @return unauthorized auth exception
     */
    public static JwtSecurityException unauthorized(String message) {
        return new JwtSecurityException(HttpStatus.UNAUTHORIZED, message);
    }

    /**
     * Creates a 403 Forbidden exception.
     *
     * @param message error message
     * @return forbidden auth exception
     */
    public static JwtSecurityException forbidden(String message) {
        return new JwtSecurityException(HttpStatus.FORBIDDEN, message);
    }


    public static JwtSecurityException internalServerError(String message) {
        return new JwtSecurityException(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }
}
