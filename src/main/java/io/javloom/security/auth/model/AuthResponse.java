package io.javloom.security.auth.model;

import io.javloom.security.token.TokenPair;
import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class AuthResponse {

    /**
     * Unique id of the authenticated user.
     */
    private final String userId;

    /**
     * Email of the authenticated user.
     */
    private final String email;

    /**
     * Permission names granted to the user.
     */
    private final List<String> permissions;

    /**
     * Generated access and refresh tokens.
     */
    private final TokenPair tokens;

}
