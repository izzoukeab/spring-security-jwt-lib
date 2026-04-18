package io.javloom.security.token;

/**
 * Discriminates access tokens from refresh tokens inside the JWT claims.
 */
public enum TokenType {
    /**
     * Short-lived token used to authenticate API requests.
     */
    ACCESS,

    /**
     * Long-lived token used to obtain a new access token without re-authentication.
     */
    REFRESH
}