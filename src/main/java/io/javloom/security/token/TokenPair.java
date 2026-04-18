package io.javloom.security.token;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class TokenPair {

    /**
     * Short-lived JWT used to authenticate requests.
     */
    private final String accessToken;

    /**
     * Long-lived opaque token used to rotate the access token.
     */
    private final String refreshToken;

    /**
     * Access token expiry in milliseconds from now.
     */
    private final long accessTokenExpiresIn;

    /**
     * Refresh token expiry in milliseconds from now.
     */
    private final long refreshTokenExpiresIn;

}
