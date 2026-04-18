package io.javloom.security.token;

import io.javloom.security.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Provides JWT creation and validation using {@link JwtProperties}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    /**
     * JWT claim names used in issued tokens.
     */
    private static final String CLAIM_TOKEN_TYPE = "typ";
    private static final String CLAIM_PERMISSIONS = "permissions";
    private static final String CLAIM_USER_ID = "userId";

    /**
     * JWT configuration values.
     */
    private final JwtProperties properties;

    /**
     * Creates a signed access token.
     *
     * @param userId      user identifier claim value
     * @param email       token subject
     * @param permissions permission values stored in claims
     * @return signed JWT
     */
    public String generateAccessToken(final String userId,
                                      final String email,
                                      final Collection<String> permissions) {
        return buildToken(userId, email, permissions, TokenType.ACCESS, properties.getAccessTokenExpiry());
    }

    /**
     * Creates a signed refresh token for the user.
     *
     * @param userId unique user identifier
     * @param email  token subject
     * @return signed JWT
     */
    public String generateRefreshToken(final String userId, final String email) {
        return buildToken(userId, email, List.of(), TokenType.REFRESH, properties.getRefreshTokenExpiry());
    }

    /**
     * Checks whether a token is well-formed, signed, and not expired.
     *
     * @param token JWT string to validate
     * @return {@code true} when valid, {@code false} otherwise
     */
    public boolean isValid(final String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("Invalid JWT token: {}", ex.getMessage());
            return false;
        }
    }

    /**
     * Checks whether a token is valid and matches the expected {@link TokenType}.
     *
     * @param token     JWT string to validate
     * @param tokenType expected token type
     * @return {@code true} when valid and type matches, {@code false} otherwise
     */
    public boolean isValid(final String token, final TokenType tokenType) {
        return isValid(token) && getTokenType(token)
                .map(t -> t == tokenType)
                .orElse(false);
    }

    /**
     * Reads the {@link TokenType} claim from a token.
     *
     * @param token JWT string to inspect
     * @return token type, or empty if missing/invalid
     */
    public Optional<TokenType> getTokenType(final String token) {
        try {
            String raw = parseClaims(token).get(CLAIM_TOKEN_TYPE, String.class);
            return Optional.of(TokenType.valueOf(raw));
        } catch (Exception ex) {
            return Optional.empty();
        }
    }

    /**
     * Builds and signs a JWT.
     *
     * @param userId      user identifier claim value
     * @param email       JWT subject
     * @param permissions permission claim values
     * @param type        token type claim value
     * @param expiryMs    token lifetime in milliseconds
     * @return signed JWT
     */
    private String buildToken(final String userId,
                              final String email,
                              final Collection<String> permissions,
                              final TokenType type,
                              final long expiryMs) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .issuer(properties.getIssuer())
                .issuedAt(new Date(now))
                .expiration(new Date(now + expiryMs))
                .claim(CLAIM_USER_ID, userId)
                .claim(CLAIM_TOKEN_TYPE, type.name())
                .claim(CLAIM_PERMISSIONS, permissions)
                .signWith(signingKey())
                .compact();
    }

    /**
     * Parses a token and returns verified {@link Claims}.
     *
     * @param token signed JWT string to parse
     * @return verified claims payload
     * @throws io.jsonwebtoken.JwtException if invalid or expired
     */
    private Claims parseClaims(final String token) {
        return Jwts.parser()
                .verifyWith(signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Derives an HMAC {@link SecretKey} from the configured secret.
     *
     * @return key used for signing and verification
     */
    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8));
    }
}
