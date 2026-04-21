package io.javloom.security.user;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
@Builder
public class SecurityUser implements UserDetails {


    /** Application user identifier. */
    private final String userId;

    /** User email used as the Spring Security username. */
    private final String email;

    /**
     * BCrypt-hashed password. Required for email/password login.
     * May be {@code null} for passwordless-only users.
     */
    private final String password;

    /** Permission names mapped to granted authorities. */
    private final List<String> permissions;

    /** Returns authorities derived from {@code permissions}. */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    /**
     * Returns the BCrypt-hashed password for credential-based login.
     * Populate this field when building a {@link SecurityUser} for email/password auth.
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Returns the email as the principal name.
     */
    @Override
    public String getUsername() {
        return email;
    }

}
