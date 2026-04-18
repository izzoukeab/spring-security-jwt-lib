package io.javloom.security.refresh;

import java.util.Optional;

/**
 * Port for refresh token persistence.
 * Implementations can back this with any store (JPA, Redis, in-memory, etc.).
 */
public interface RefreshTokenStore {

    /**
     * Persists a new refresh token record.
     *
     * @param token the token to store
     * @return the saved token (may include generated fields set by the store)
     */
    RefreshToken save(RefreshToken token);

    /**
     * Finds a non-revoked, non-expired token by its hash.
     *
     * @param tokenHash SHA-256 hash of the raw JWT string
     * @return the matching active token, or empty if not found or inactive
     */
    Optional<RefreshToken> findActiveByHash(String tokenHash);

    /**
     * Finds any token by its hash, regardless of revocation or expiry status.
     *
     * @param tokenHash SHA-256 hash of the raw JWT string
     * @return the matching token, or empty if not found
     */
    Optional<RefreshToken> findByHash(String tokenHash);

    /**
     * Revokes a single token record by its unique id.
     *
     * @param id string representation of the token's {@link java.util.UUID}
     */
    void revokeById(String id);

    /**
     * Revokes all tokens belonging to the given rotation family.
     * Called when a reuse attack is detected to invalidate the entire chain.
     *
     * @param familyId the shared family identifier
     */
    void revokeAllByFamilyId(String familyId);

    /**
     * Revokes all active tokens issued to the given user (e.g. on logout-all).
     *
     * @param userId the user whose tokens should be revoked
     */
    void revokeAllByUserId(String userId);

    /**
     * Removes all token records that have passed their {@code expiresAt} timestamp.
     * Intended for periodic housekeeping jobs.
     */
    void deleteAllExpired();

}
