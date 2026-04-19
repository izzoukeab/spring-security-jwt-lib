package io.javloom.security.auth.model;

import io.javloom.commons.validation.annotation.NoHtml;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Request payload to verify an OTP code and complete passwordless authentication.
 */
@Getter
@NoArgsConstructor
public class OtpVerifyRequest {

    /**
     * E.164 formatted phone number — must match the number used in {@link OtpRequest}.
     */
    @NotBlank
    @NoHtml
    @Pattern(
            regexp = "^\\+[1-9]\\d{6,14}$",
            message = "must be a valid E.164 phone number")
    private String phone;

    /**
     * One-time password received by SMS.
     */
    @NotBlank
    @Size(min = 4, max = 8)
    private String code;
}