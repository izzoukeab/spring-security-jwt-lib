package io.javloom.security.user;

import java.util.Optional;

/**
 * Loads security users from the consuming application's data source.
 */
public interface SecurityUserService {

    /**
     * Finds a user by email for email/password authentication.
     *
     * @param email user email
     * @return matching user, or empty if not found
     */
    Optional<SecurityUser> findByEmail(String email);

    /**
     * Finds a user by phone for passwordless SMS authentication.
     *
     * @param phone phone number in E.164 format (e.g. +33612345678)
     * @return matching user, or empty if not found
     */
    Optional<SecurityUser> findByPhone(String phone);

}
