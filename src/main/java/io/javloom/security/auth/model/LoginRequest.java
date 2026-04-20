package io.javloom.security.auth.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Request body for email-and-password login.
 */
@Getter
@NoArgsConstructor
public class LoginRequest {

    /**
     * Email used to log in.
     */
    @Email
    @NotBlank
    private String email;

    /**
     * Password used to log in. Do not log or store this value.
     */
    @NotBlank
    private String password;

}
