package io.javloom.security.config;

import io.javloom.security.filter.JwtAuthenticationFilter;
import io.javloom.security.permission.CustomPermissionEvaluator;
import io.javloom.security.token.JwtTokenProvider;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Autoconfiguration for Javloom JWT security.
 * Activated automatically when the lib is on the classpath.
 */
@Getter
@AutoConfiguration
@EnableMethodSecurity
@RequiredArgsConstructor
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityAutoConfiguration {

    private final CustomPermissionEvaluator customPermissionEvaluator;

    /**
     * Registers the JWT token provider.
     */
    @Bean
    public JwtTokenProvider jwtTokenProvider(final JwtProperties properties) {
        return new JwtTokenProvider(properties);
    }

    /**
     * Registers the JWT authentication filter.
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(final JwtTokenProvider tokenProvider) {
        return new JwtAuthenticationFilter(tokenProvider);
    }

    /**
     * Wires the custom {@link CustomPermissionEvaluator} into Spring's method security.
     */
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            final CustomPermissionEvaluator customPermissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler =
                new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(customPermissionEvaluator);
        return handler;
    }

    @Bean
    public CustomPermissionEvaluator customPermissionEvaluator() {
        return new CustomPermissionEvaluator();
    }

}