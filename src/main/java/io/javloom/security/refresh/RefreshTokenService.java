package io.javloom.security.refresh;

import io.javloom.commons.exception.ApiException;
import io.javloom.commons.exception.ExceptionName;
import io.javloom.security.config.JwtProperties;
import io.javloom.security.token.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Handles refresh token lifecycle: creation, rotation, reuse detection, and revocation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenStore store;
    private final JwtTokenProvider tokenProvider;
    private final JwtProperties properties;

    /**
     * Issues a new refresh token for the given user and starts a new token family.
     *
     * @param userId user identifier
     * @param email  user email
     * @return raw refresh token JWT
     */
    public String createRefreshToken(final String userId, final String email) {
        String rawToken = tokenProvider.generateRefreshToken(userId, email);
        String tokenHash = hash(rawToken);
        String familyId = UUID.randomUUID().toString();

        RefreshToken token = RefreshToken.builder()
                .id(UUID.randomUUID().toString())
                .tokenHash(tokenHash)
                .userId(userId)
                .email(email)
                .familyId(familyId)
                .generation(1)
                .revoked(false)
                .expiresAt(Instant.now().plusMillis(properties.getRefreshTokenExpiry()))
                .createdAt(Instant.now())
                .build();

        store.save(token);
        return rawToken;
    }

    /**
     * Validates {@code rawToken}, revokes it, and issues a replacement in the same family.
     * If the token was already revoked (reuse attack), the entire family is revoked.
     *
     * @param rawToken current raw refresh token JWT
     * @return new raw refresh token JWT
     * @throws ApiException on invalid, expired, or reused token
     */
    public String rotate(final String rawToken) {
        String tokenHash = hash(rawToken);

        // Check for reuse attack — token exists but is already revoked
        store.findByHash(tokenHash).ifPresent(existing -> {
            if (existing.isRevoked()) {
                log.warn("Refresh token reuse detected — revoking family: {}", existing.getFamilyId());
                store.revokeAllByFamilyId(existing.getFamilyId());
                throw ApiException.of(
                        HttpStatus.UNAUTHORIZED,
                        "Refresh token reuse detected — all sessions revoked",
                        ExceptionName.UnauthorizedException
                );
            }
        });

        RefreshToken current = store.findActiveByHash(tokenHash)
                .orElseThrow(() -> ApiException.of(
                        HttpStatus.UNAUTHORIZED,
                        "Refresh token is invalid or expired",
                        ExceptionName.UnauthorizedException
                ));

        // Revoke current token
        store.revokeById(current.getId());

        // Issue new token in same family, incremented generation
        String newRawToken = tokenProvider.generateRefreshToken(current.getUserId(), current.getEmail());
        String newTokenHash = hash(newRawToken);

        RefreshToken rotated = RefreshToken.builder()
                .id(UUID.randomUUID().toString())
                .tokenHash(newTokenHash)
                .userId(current.getUserId())
                .email(current.getEmail())
                .familyId(current.getFamilyId())
                .generation(current.getGeneration() + 1)
                .revoked(false)
                .expiresAt(Instant.now().plusMillis(properties.getRefreshTokenExpiry()))
                .createdAt(Instant.now())
                .build();

        store.save(rotated);
        log.debug("Refresh token rotated — family: {}, generation: {}", rotated.getFamilyId(), rotated.getGeneration());

        return newRawToken;
    }

    /**
     * Revokes all refresh tokens for the given user (e.g. on logout).
     *
     * @param userId user identifier
     */
    public void revokeAll(final String userId) {
        store.revokeAllByUserId(userId);
        log.debug("All refresh tokens revoked for user: {}", userId);
    }

    /**
     * Returns the hex-encoded SHA-256 hash of {@code rawToken}.
     *
     * @param rawToken raw token value
     * @return hex SHA-256 hash
     */
    public String hash(final String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException ex) {
            throw ApiException.of(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "SHA-256 algorithm not available",
                    ExceptionName.InternalServerErrorException
            );
        }
    }
}