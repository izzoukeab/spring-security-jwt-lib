package io.javloom.security.filter;

import io.javloom.security.token.JwtTokenProvider;
import io.javloom.security.token.TokenType;
import io.javloom.security.user.SecurityUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Validates Bearer JWTs and sets authentication in {@link SecurityContextHolder}.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(@NonNull final HttpServletRequest request,
                                    @NonNull final HttpServletResponse response,
                                    @NonNull final FilterChain filterChain)
            throws ServletException, IOException {

        extractToken(request).ifPresent(token -> authenticate(token, request));
        filterChain.doFilter(request, response);
    }

    /**
     * Extracts a Bearer token from the Authorization header.
     *
     * @param request incoming HTTP request
     * @return token value without the Bearer prefix, or empty if absent/invalid
     */
    private java.util.Optional<String> extractToken(final HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(header.substring(BEARER_PREFIX.length()));
    }

    /**
     * Validates a token and sets request authentication when valid.
     *
     * @param token   raw JWT string
     * @param request current HTTP request
     */
    private void authenticate(final String token, final HttpServletRequest request) {
        if (!tokenProvider.isValid(token, TokenType.ACCESS)) {
            log.debug("Invalid or non-access JWT token — skipping authentication");
            return;
        }

        try {
            String userId = tokenProvider.getUserId(token);
            String email = tokenProvider.getEmail(token);
            List<String> perms = tokenProvider.getPermissions(token);

            SecurityUser securityUser = SecurityUser.builder()
                    .userId(userId)
                    .email(email)
                    .permissions(perms)
                    .build();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            securityUser,
                            null,
                            securityUser.getAuthorities());

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Authenticated user: {} with permissions: {}", email, perms);

        } catch (Exception ex) {
            log.warn("Failed to authenticate JWT token: {}", ex.getMessage());
        }
    }
}