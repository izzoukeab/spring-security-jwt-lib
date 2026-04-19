package io.javloom.security.permission;

/**
 * Contract for application permission constants.
 */
public interface CustomPermission {

    /**
     * Returns the permission name as stored in JWT claims.
     *
     * @return permission name
     */
    String getName();
}