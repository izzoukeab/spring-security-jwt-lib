package io.javloom.security.refresh;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Immutable stored refresh token used for token-family rotation and reuse detection.
 */
@Getter
@Builder
public class RefreshToken {

    /**
     * Unique token record identifier.
     */
    private final String id;

    /**
     * SHA-256 hash of the raw JWT; the raw token is never stored.
     */
    private final String tokenHash;

    /**
     * Identifier of the user this token belongs to.
     */
    private final String userId;

    /**
     * Email of the user this token belongs to.
     */
    private final String email;

    /**
     * Shared identifier for all tokens in one rotation family.
     */
    private final String familyId;

    /**
     * Family rotation counter, incremented on each refresh.
     */
    private final int generation;

    /**
     * {@code true} when this token is revoked.
     */
    private final boolean revoked;

    /**
     * Expiration timestamp after which the token is invalid.
     */
    private final Instant expiresAt;

    /**
     * Creation timestamp for this token record.
     */
    private final Instant createdAt;

}
