package io.javloom.security.auth.passwordless;

import java.time.Duration;
import java.util.Optional;

/**
 * Port for OTP storage — implement with Redis, DB, or in-memory.
 */
public interface OtpStore {

    /**
     * Saves an OTP code for the given phone number with a TTL.
     *
     * @param phone E.164 phone number
     * @param code  OTP code
     * @param ttl   time-to-live
     */
    void save(String phone, String code, Duration ttl);

    /**
     * Finds the current OTP for a phone number.
     *
     * @param phone E.164 phone number
     * @return optional OTP code
     */
    Optional<String> find(String phone);

    /**
     * Deletes the OTP for a phone number — called after successful verification.
     *
     * @param phone E.164 phone number
     */
    void delete(String phone);
}