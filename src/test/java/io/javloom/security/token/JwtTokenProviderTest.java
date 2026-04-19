package io.javloom.security.token;

import io.javloom.security.config.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenProviderTest {

    private JwtTokenProvider tokenProvider;

    @BeforeEach
    void setup() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-secret-key-must-be-at-least-32-chars!!");
        properties.setAccessTokenExpiry(900_000L);
        properties.setRefreshTokenExpiry(604_800_000L);
        properties.setIssuer("javloom-test");
        tokenProvider = new JwtTokenProvider(properties);
    }

    // --- Access token ---

    @Test
    void should_generate_valid_access_token() {
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", List.of("USER_READ"));
        assertThat(token).isNotBlank();
        assertThat(tokenProvider.isValid(token)).isTrue();
    }

    @Test
    void should_extract_email_from_access_token() {
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", List.of());
        assertThat(tokenProvider.getEmail(token)).isEqualTo("user@test.com");
    }

    @Test
    void should_extract_userId_from_access_token() {
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", List.of());
        assertThat(tokenProvider.getUserId(token)).isEqualTo("user1");
    }

    @Test
    void should_extract_permissions_from_access_token() {
        List<String> perms = List.of("USER_READ", "ORDER_WRITE");
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", perms);
        assertThat(tokenProvider.getPermissions(token)).containsExactlyInAnyOrderElementsOf(perms);
    }

    @Test
    void should_return_access_token_type() {
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", List.of());
        assertThat(tokenProvider.getTokenType(token)).contains(TokenType.ACCESS);
    }

    @Test
    void should_validate_access_token_with_correct_type() {
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", List.of());
        assertThat(tokenProvider.isValid(token, TokenType.ACCESS)).isTrue();
        assertThat(tokenProvider.isValid(token, TokenType.REFRESH)).isFalse();
    }

    // --- Refresh token ---

    @Test
    void should_generate_valid_refresh_token() {
        String token = tokenProvider.generateRefreshToken("user1", "user@test.com");
        assertThat(token).isNotBlank();
        assertThat(tokenProvider.isValid(token)).isTrue();
    }

    @Test
    void should_return_refresh_token_type() {
        String token = tokenProvider.generateRefreshToken("user1", "user@test.com");
        assertThat(tokenProvider.getTokenType(token)).contains(TokenType.REFRESH);
    }

    @Test
    void should_validate_refresh_token_with_correct_type() {
        String token = tokenProvider.generateRefreshToken("user1", "user@test.com");
        assertThat(tokenProvider.isValid(token, TokenType.REFRESH)).isTrue();
        assertThat(tokenProvider.isValid(token, TokenType.ACCESS)).isFalse();
    }

    /*
    @Test
    void should_extract_jti_from_refresh_token() {
        String token = tokenProvider.generateRefreshToken("user1", "user@test.com");
        assertThat(tokenProvider.getJwtId(token)).isNotBlank();
    }
*/
    // --- Invalid tokens ---

    @Test
    void should_return_false_for_invalid_token() {
        assertThat(tokenProvider.isValid("not.a.jwt")).isFalse();
    }

    @Test
    void should_return_false_for_tampered_token() {
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", List.of());
        assertThat(tokenProvider.isValid(token + "tampered")).isFalse();
    }

    @Test
    void should_return_false_for_blank_token() {
        assertThat(tokenProvider.isValid("")).isFalse();
    }
}