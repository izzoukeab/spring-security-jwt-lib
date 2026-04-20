package io.javloom.security.refresh;

import io.javloom.security.config.JwtProperties;
import io.javloom.security.exception.JwtSecurityException;
import io.javloom.security.token.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenStore store;

    private RefreshTokenService service;
    private JwtTokenProvider    tokenProvider;

    @BeforeEach
    void setup() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-secret-key-must-be-at-least-32-chars!!");
        properties.setAccessTokenExpiry(900_000L);
        properties.setRefreshTokenExpiry(604_800_000L);
        properties.setIssuer("javloom-test");
        tokenProvider = new JwtTokenProvider(properties);
        service = new RefreshTokenService(store, tokenProvider, properties);
    }

    @Test
    void should_create_and_persist_refresh_token() {
        when(store.save(any())).thenAnswer(inv -> inv.getArgument(0));

        String rawToken = service.createRefreshToken("user1", "user@test.com");

        assertThat(rawToken).isNotBlank();
        verify(store).save(any(RefreshToken.class));
    }

    @Test
    void should_rotate_valid_refresh_token() {
        when(store.save(any())).thenAnswer(inv -> inv.getArgument(0));
        String rawToken = service.createRefreshToken("user1", "user@test.com");
        String hash = service.hash(rawToken);

        RefreshToken stored = RefreshToken.builder()
                .id("id-1")
                .tokenHash(hash)
                .userId("user1")
                .email("user@test.com")
                .familyId("family-1")
                .generation(1)
                .revoked(false)
                .expiresAt(Instant.now().plusSeconds(3600))
                .createdAt(Instant.now())
                .build();

        when(store.findByHash(hash)).thenReturn(Optional.of(stored));
        when(store.findActiveByHash(hash)).thenReturn(Optional.of(stored));

        String newToken = service.rotate(rawToken);

        assertThat(newToken).isNotBlank();
        assertThat(newToken).isNotEqualTo(rawToken);
        verify(store).revokeById("id-1");
        //verify(store).save(any(RefreshToken.class));
    }

    @Test
    void should_throw_when_token_not_found() {
        when(store.save(any())).thenAnswer(inv -> inv.getArgument(0));
        String rawToken = service.createRefreshToken("user1", "user@test.com");
        String hash = service.hash(rawToken);

        when(store.findByHash(hash)).thenReturn(Optional.empty());
        when(store.findActiveByHash(hash)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.rotate(rawToken))
                .isInstanceOf(JwtSecurityException.class)
                .hasMessageContaining("invalid or expired");
    }

    @Test
    void should_revoke_family_on_reuse_attack() {
        when(store.save(any())).thenAnswer(inv -> inv.getArgument(0));
        String rawToken = service.createRefreshToken("user1", "user@test.com");
        String hash = service.hash(rawToken);

        RefreshToken revoked = RefreshToken.builder()
                .id("id-1")
                .tokenHash(hash)
                .userId("user1")
                .email("user@test.com")
                .familyId("family-1")
                .generation(1)
                .revoked(true)
                .expiresAt(Instant.now().plusSeconds(3600))
                .createdAt(Instant.now())
                .build();

        when(store.findByHash(hash)).thenReturn(Optional.of(revoked));

        assertThatThrownBy(() -> service.rotate(rawToken))
                .isInstanceOf(JwtSecurityException.class)
                .hasMessageContaining("reuse detected");

        verify(store).revokeAllByFamilyId("family-1");
    }

    @Test
    void should_revoke_all_tokens_on_logout() {
        service.revokeAll("user1");
        verify(store).revokeAllByUserId("user1");
    }

    @Test
    void should_produce_consistent_hash() {
        String raw = "some-token-value";
        assertThat(service.hash(raw)).isEqualTo(service.hash(raw));
    }

    @Test
    void should_produce_different_hashes_for_different_tokens() {
        assertThat(service.hash("token-a")).isNotEqualTo(service.hash("token-b"));
    }
}