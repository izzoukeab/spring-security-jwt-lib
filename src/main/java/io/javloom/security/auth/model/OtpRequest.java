package io.javloom.security.auth.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Request payload to initiate passwordless SMS authentication.
 * Triggers OTP generation and SMS dispatch.
 */
@Getter
@NoArgsConstructor
public class OtpRequest {

    /**
     * E.164 formatted phone number.
     * Examples: +33612345678, +212661234567
     */
    @NotBlank
    @Pattern(
            regexp = "^\\+[1-9]\\d{6,14}$",
            message = "must be a valid E.164 phone number (e.g. +33612345678)")
    private String phone;
}