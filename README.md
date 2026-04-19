# spring-security-jwt-lib 🔐

Modern JWT auth building blocks for Spring Boot apps.

You get:

- ⚡ Access token generation + validation
- 🔁 Refresh token rotation with reuse-attack detection
- 🛡️ Permission-based authorization helpers
- 📱 Optional passwordless OTP flow (SMS)
- 🧩 Clear extension ports for your own persistence and providers

> This library is intentionally composable: it gives you core security components, while your app owns storage, transports, and HTTP endpoints.

## 📚 Table of contents

- [✨ What this library does](#-what-this-library-does)
- [🧱 Core components](#-core-components)
- [🔄 Token lifecycle](#-token-lifecycle)
- [✅ Requirements](#-requirements)
- [📦 Installation](#-installation)
- [⚙️ Configuration](#-configuration)
- [🛠️ Integration guide](#integration-guide)
- [🚀 Usage examples](#-usage-examples)
- [🔐 Permissions and authorization](#-permissions-and-authorization)
- [🧩 Contracts you must implement](#-contracts-you-must-implement)
- [🗃️ Data model recommendations](#data-model-recommendations)
- [🧪 Testing checklist](#-testing-checklist)
- [🧯 Troubleshooting](#-troubleshooting)
- [🔒 Security best practices](#-security-best-practices)

## ✨ What this library does

This library centralizes JWT auth logic so each service does not reinvent it.

1. Signs and validates JWT access/refresh tokens.
2. Extracts claims: `email`, `userId`, `permissions`, token type.
3. Rotates refresh tokens by family + generation.
4. Detects refresh-token replay and revokes the full token family.
5. Provides a request filter that authenticates Bearer access tokens.
6. Supports permission checks from JWT claims.
7. Supports OTP send/verify via pluggable store + SMS ports.

## 🧱 Core components

| Component | Purpose |
|---|---|
| `JwtTokenProvider` | Build/verify JWTs and read claims |
| `RefreshTokenService` | Create/rotate/revoke refresh tokens |
| `AuthService` | Login, OTP login, refresh, logout orchestration |
| `JwtAuthenticationFilter` | Reads Bearer token and populates `SecurityContextHolder` |
| `CustomPermissionEvaluator` | Evaluates permission checks against `SecurityUser.permissions` |
| `SecurityAutoConfiguration` | Registers core beans and method-security wiring |
| `JwtProperties` | Typed config under `javloom.jwt.*` |

## 🔄 Token lifecycle

### Login / OTP verify flow

1. `AuthService` resolves user via `SecurityUserService`.
2. `JwtTokenProvider` creates access token.
3. `RefreshTokenService` creates refresh token and persists only a hash.
4. API returns `AuthResponse` with a `TokenPair`.

### Request auth flow

1. `JwtAuthenticationFilter` reads `Authorization: Bearer <token>`.
2. Validates token and enforces `TokenType.ACCESS`.
3. Extracts claims (`userId`, `email`, `permissions`).
4. Builds `SecurityUser` and sets Spring Security authentication context.

### Refresh rotation flow

1. Client sends current refresh token.
2. Service hashes token and loads stored record.
3. If token is already revoked => reuse attack => revoke whole family.
4. If token is active => revoke current token + issue next generation.

## ✅ Requirements

- Java 21
- Spring Boot 3.4+
- Spring Security 6+

## 📦 Installation

Add the dependency to your app:

```xml
<dependency>
  <groupId>io.javloom</groupId>
  <artifactId>spring-security-jwt-lib</artifactId>
  <version>0.0.1-SNAPSHOT</version>
</dependency>
```

If you use library-thrown `ApiException`, include:

```xml
<dependency>
  <groupId>io.javloom</groupId>
  <artifactId>spring-rest-commons</artifactId>
  <version>0.0.1-SNAPSHOT</version>
</dependency>
```

## ⚙️ Configuration

`application.yml`:

```yaml
javloom:
  jwt:
    secret: "replace-with-a-long-random-secret-at-least-32-chars"
    access-token-expiry: 900000
    refresh-token-expiry: 604800000
    issuer: "your-service-name"
```

### Property reference

| Property | Default | Description |
|---|---:|---|
| `javloom.jwt.secret` | none | HMAC signing secret |
| `javloom.jwt.access-token-expiry` | `900000` | Access token TTL in ms (15 min) |
| `javloom.jwt.refresh-token-expiry` | `604800000` | Refresh token TTL in ms (7 days) |
| `javloom.jwt.issuer` | `javloom` | JWT issuer (`iss`) |


<a id="integration-guide"></a>

## 🛠️ Integration guide

### 1) Register configuration

`SecurityAutoConfiguration` exists in the library. If your app does not pick it up automatically, import it manually:

```java
@Configuration
@Import(io.javloom.security.config.SecurityAutoConfiguration.class)
public class JwtLibConfig {
}
```

### 2) Implement required ports

Required in your app:

- `SecurityUserService`
- `RefreshTokenStore`

Optional (passwordless OTP):

- `OtpStore`
- `SmsPort`

### 3) Add JWT filter to your chain

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
```

### 4) Expose your own API endpoints

This library does not impose controllers. You define your REST endpoints and delegate to `AuthService`.

## 🚀 Usage examples

```java
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request.getEmail(), request.getPassword());
    }

    @PostMapping("/otp/send")
    public void sendOtp(@Valid @RequestBody OtpRequest request) {
        authService.initiateOtpLogin(request.getPhone());
    }

    @PostMapping("/otp/verify")
    public AuthResponse verifyOtp(@Valid @RequestBody OtpVerifyRequest request) {
        return authService.verifyOtpLogin(request.getPhone(), request.getCode());
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestHeader("Authorization") String bearer) {
        String refreshToken = bearer.substring("Bearer ".length());
        return authService.refresh(refreshToken);
    }

    @PostMapping("/logout")
    public void logout(@AuthenticationPrincipal SecurityUser user) {
        authService.logout(user.getUserId());
    }
}
```

## 🔐 Permissions and authorization

Access tokens carry a `permissions` claim. The filter maps this to granted authorities.

Use standard authority checks:

```java
@PreAuthorize("hasAuthority('ORDER_READ')")
@GetMapping("/orders/{id}")
public OrderDto getOrder(@PathVariable String id) {
    return service.getById(id);
}
```

Or use evaluator-style checks:

```java
@PreAuthorize("hasPermission(null, 'ORDER_READ')")
public void readOrder() {
}
```

`@HasPermission("ORDER_READ")` is also available when your Spring Security setup supports annotation template resolution.

## 🧩 Contracts you must implement

### `SecurityUserService`

```java
public interface SecurityUserService {
    Optional<SecurityUser> findByEmail(String email);
    Optional<SecurityUser> findByPhone(String phone);
}
```

Notes:

- Put app permissions in `SecurityUser.permissions`.
- `findByPhone` is required for OTP flow.
- `findByEmail` is required for login/refresh user resolution.

### `RefreshTokenStore`

```java
public interface RefreshTokenStore {
    RefreshToken save(RefreshToken token);
    Optional<RefreshToken> findActiveByHash(String tokenHash);
    Optional<RefreshToken> findByHash(String tokenHash);
    void revokeById(String id);
    void revokeAllByFamilyId(String familyId);
    void revokeAllByUserId(String userId);
    void deleteAllExpired();
}
```

Notes:

- Store `tokenHash`, never raw refresh token.
- `findActiveByHash` must enforce `revoked = false` and `expiresAt > now`.
- Run `deleteAllExpired()` on a schedule.

### OTP contracts (optional)

```java
public interface OtpStore {
    void save(String phone, String code, Duration ttl);
    Optional<String> find(String phone);
    void delete(String phone);
}

public interface SmsPort {
    void send(String phone, String message);
}
```

<a id="data-model-recommendations"></a>

## 🗃️ Data model recommendations

For refresh token persistence, index at least:

- `token_hash` (unique)
- `family_id`
- `user_id`
- `expires_at`
- `revoked`

Suggested columns:

- `id` (string/UUID)
- `token_hash` (string)
- `user_id` (string)
- `email` (string)
- `family_id` (string)
- `generation` (int)
- `revoked` (boolean)
- `expires_at` (timestamp)
- `created_at` (timestamp)

## 🧪 Testing checklist

1. Login/OTP verify returns access + refresh tokens.
2. Protected endpoints accept valid access token.
3. Invalid/expired access token is rejected.
4. Refresh rotates token and revokes prior token.
5. Reused refresh token revokes full family.
6. Permission-protected endpoints allow/deny correctly.

Run this library tests:

```bash
./mvnw test
```

## 🧯 Troubleshooting

### `Invalid JWT token`

- Verify `javloom.jwt.secret` is consistent in issuer + validator.
- Verify Bearer header format.
- Ensure access endpoints are not using refresh tokens.

### Refresh always fails as invalid/expired

- Validate `RefreshTokenStore.findActiveByHash` logic.
- Validate UTC expiration checks.
- Validate SHA-256 hashing of raw refresh token.

### Permission checks always denied

- Check `permissions` claim exists in access token.
- Check `SecurityUser.permissions` contains expected values.
- Check JWT filter order in `SecurityFilterChain`.

### OTP verification fails

- Check OTP TTL + delete-on-success behavior in `OtpStore`.
- Check E.164 phone normalization consistency.

## 🔒 Security best practices

- Use high-entropy secrets (32+ random bytes).
- Keep short access-token TTL.
- Store hashed refresh tokens only.
- Revoke token families on reuse detection.
- Enforce HTTPS everywhere.
- Rate-limit login/OTP/refresh endpoints.
- Add audit logging and anomaly detection.
- Keep dependencies patched and scan regularly.

---

Built for teams that want secure defaults and clean extension points 😎
