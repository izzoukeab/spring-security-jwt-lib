package io.javloom.security.permission;

import io.javloom.security.user.SecurityUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PermissionEvaluatorTest {

    private CustomPermissionEvaluator evaluator;

    @BeforeEach
    void setup() {
        evaluator = new CustomPermissionEvaluator();
    }

    private Authentication authWith(List<String> permissions) {
        SecurityUser user = SecurityUser.builder()
                .userId("user1")
                .email("user@test.com")
                .permissions(permissions)
                .build();
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    }

    @Test
    void should_grant_permission_when_user_has_it() {
        Authentication auth = authWith(List.of("USER_READ", "ORDER_WRITE"));
        assertThat(evaluator.hasPermission(auth, null, "USER_READ")).isTrue();
    }

    @Test
    void should_deny_permission_when_user_does_not_have_it() {
        Authentication auth = authWith(List.of("USER_READ"));
        assertThat(evaluator.hasPermission(auth, null, "ADMIN_ACCESS")).isFalse();
    }

    @Test
    void should_deny_when_authentication_is_null() {
        assertThat(evaluator.hasPermission(null, null, "USER_READ")).isFalse();
    }

    @Test
    void should_deny_when_permission_is_not_string() {
        Authentication auth = authWith(List.of("USER_READ"));
        assertThat(evaluator.hasPermission(auth, null, 42)).isFalse();
    }

    @Test
    void should_deny_when_principal_is_not_security_user() {
        Authentication auth = new UsernamePasswordAuthenticationToken(
                "anonymous", null, List.of());
        assertThat(evaluator.hasPermission(auth, null, "USER_READ")).isFalse();
    }

    @Test
    void should_delegate_target_id_check_to_name_based_check() {
        Authentication auth = authWith(List.of("USER_READ"));
        assertThat(evaluator.hasPermission(auth, "target-id", "User", "USER_READ")).isTrue();
    }
}