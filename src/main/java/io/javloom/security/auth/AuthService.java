package io.javloom.security.auth;

import io.javloom.security.auth.model.AuthResponse;
import io.javloom.security.auth.passwordless.OtpService;
import io.javloom.security.exception.JwtSecurityException;
import io.javloom.security.refresh.RefreshTokenService;
import io.javloom.security.token.JwtTokenProvider;
import io.javloom.security.token.TokenPair;
import io.javloom.security.token.TokenType;
import io.javloom.security.user.SecurityUser;
import io.javloom.security.user.SecurityUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Orchestrates all authentication flows:
 * email/password login, passwordless SMS, token refresh, and logout.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final SecurityUserService userService;
    private final OtpService otpService;
    private final PasswordEncoder passwordEncoder;

    // --- Email / Password ---

    /**
     * Authenticates a user with email and password.
     *
     * @param email    user email
     * @param password raw password
     * @return auth response with token pair and user info
     * @throws JwtSecurityException if credentials are invalid
     */
    public AuthResponse login(final String email, final String password) {
        SecurityUser user = userService.findByEmail(email).orElseThrow(JwtSecurityException::unauthorized);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.warn("Failed login attempt for email: {}", email);
            throw JwtSecurityException.unauthorized();
        }

        return buildAuthResponse(user);
    }

    // --- Passwordless SMS ---

    /**
     * Initiates passwordless authentication by sending an OTP to the given phone.
     *
     * @param phone E.164 phone number
     */
    public void initiateOtpLogin(final String phone) {
        otpService.sendOtp(phone);
    }

    /**
     * Completes passwordless authentication by verifying the OTP.
     *
     * @param phone E.164 phone number
     * @param code  submitted OTP code
     * @return auth response with token pair and user info
     * @throws ApiException if OTP is invalid or user not found
     */
    public AuthResponse verifyOtpLogin(final String phone, final String code) {
        otpService.verifyOtp(phone, code);

        SecurityUser user = userService.findByPhone(phone).orElseThrow(JwtSecurityException::unauthorized);

        return buildAuthResponse(user);
    }

    // --- Token refresh ---

    /**
     * Rotates a refresh token and issues a new token pair.
     *
     * @param refreshToken current raw refresh token
     * @return new auth response with rotated token pair
     * @throws JwtSecurityException if refresh token is invalid or reuse is detected
     */
    public AuthResponse refresh(final String refreshToken) {
        if (!tokenProvider.isValid(refreshToken, TokenType.REFRESH)) {
            throw JwtSecurityException.unauthorized("Invalid refresh token");
        }

        String email = tokenProvider.getEmail(refreshToken);

        SecurityUser user = userService.findByEmail(email)
                .orElseThrow(() -> JwtSecurityException.unauthorized("User not found"));

        String newRefreshToken = refreshTokenService.rotate(refreshToken);
        String newAccessToken = tokenProvider.generateAccessToken(
                user.getUserId(),
                user.getEmail(),
                user.getPermissions()
        );

        TokenPair tokens = TokenPair.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .accessTokenExpiresIn(900_000L)
                .refreshTokenExpiresIn(604_800_000L)
                .build();

        return AuthResponse.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .permissions(user.getPermissions())
                .tokens(tokens)
                .build();
    }

    // --- Logout ---

    /**
     * Revokes all refresh tokens for the given user — invalidates all sessions.
     *
     * @param userId user identifier
     */
    public void logout(final String userId) {
        refreshTokenService.revokeAll(userId);
        log.debug("User logged out — all sessions revoked: {}", userId);
    }

    // --- Internal ---

    private AuthResponse buildAuthResponse(final SecurityUser user) {
        String accessToken = tokenProvider.generateAccessToken(
                user.getUserId(),
                user.getEmail(),
                user.getPermissions()
        );
        String refreshToken = refreshTokenService.createRefreshToken(
                user.getUserId(),
                user.getEmail()
        );

        TokenPair tokens = TokenPair.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpiresIn(900_000L)
                .refreshTokenExpiresIn(604_800_000L)
                .build();

        return AuthResponse.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .permissions(user.getPermissions())
                .tokens(tokens)
                .build();
    }

}