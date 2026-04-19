package io.javloom.security.permission;

import io.javloom.security.user.SecurityUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * Evaluates whether the current user has a given permission.
 * Used by Spring Security permission expressions.
 */
@Slf4j
@Component
@Qualifier("customPermissionEvaluator")
public class CustomPermissionEvaluator implements PermissionEvaluator {

    /**
     * Checks whether the current user has the requested permission name.
     *
     * @param authentication current authentication
     * @param targetDomainObject target object (unused)
     * @param permission permission name to check
     * @return {@code true} if granted, otherwise {@code false}
     */
    @Override
    public boolean hasPermission(final Authentication authentication,
                                 final Object targetDomainObject,
                                 final Object permission) {
        if (authentication == null || !(permission instanceof String permissionName)) {
            return false;
        }

        if (!(authentication.getPrincipal() instanceof SecurityUser securityUser)) {
            return false;
        }

        boolean granted = securityUser.getPermissions().contains(permissionName);
        log.debug("Permission check — user: {}, permission: {}, granted: {}",
                securityUser.getEmail(), permissionName, granted);

        return granted;
    }

    /**
     * Checks permission when target id/type values are provided.
     * Delegates to the name-based permission check.
     *
     * @param authentication current authentication
     * @param targetId target object id (unused)
     * @param targetType target object type (unused)
     * @param permission permission name to check
     * @return {@code true} if granted, otherwise {@code false}
     */
    @Override
    public boolean hasPermission(final Authentication authentication,
                                 final Serializable targetId,
                                 final String targetType,
                                 final Object permission) {
        return hasPermission(authentication, null, permission);
    }
}