package io.javloom.security.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * JWT settings bound to {@code javloom.jwt}.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "javloom.jwt")
public class JwtProperties {

    /**
     * Signing secret used for JWT HMAC.
     */
    @NotBlank(message = "JWT secret must not be blank")
    private String secret;

    /**
     * Access token lifetime in milliseconds (default: 900000 = 15 minutes).
     */
    @Min(value = 60000, message = "Access token expiry must be at least 60 seconds")
    private long accessTokenExpiry = 900_000L;

    /**
     * Refresh token lifetime in milliseconds (default: 604800000 = 7 days).
     */
    @Min(value = 60000, message = "Refresh token expiry must be at least 60 seconds")
    private long refreshTokenExpiry = 604_800_000L;

    /**
     * JWT {@code iss} claim value (default: {@code "javloom"}).
     */
    private String issuer = "javloom";
}
