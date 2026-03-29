# Architecture

## Modules

- `auth-core`: domain models, SPI contracts, exceptions.
- `auth-security`: JWT, login handlers, controller, exception handling, security config.
- `auth-persistence`: JDBC implementations for user lookup, registration, password management, login-attempt lock strategy, management, audit, blacklist.
- `auth-qr`: QR login scene service with JDBC cleanup support.
- `auth-social-google`: Google ID token provider with mock fallback.
- `auth-social-wechat`: WeChat provider module with real code exchange and mock fallback.
- `auth-audit`: fallback logging audit publisher.
- `auth-autoconfigure`: Spring Boot starter wiring.
- `auth-spring-boot-starter`: aggregate starter artifact.
- `auth-demo`: runnable integration sample.

## Runtime Flow

### Password Login

1. `AuthController` receives `/auth/login/password`.
2. `AuthenticationDispatcher` routes to `PasswordAuthenticationHandler`.
3. `UserLookupService` loads credential view.
4. `LoginAttemptService` records failure or clears attempts on success.
5. `PermissionService` enriches roles and permissions.
6. `TokenService` issues JWT access and refresh tokens.
7. `AuditEventPublisher` writes login and security events.

### Password Change / Reset

1. Controller validates request and identity.
2. `PasswordManagementService` validates password strength.
3. JDBC layer updates `sys_auth.credential_hash`.
4. JDBC layer increments `sys_user.password_version` and clears lock state.

### QR Login

1. `QrLoginService.createScene()` creates a pending scene in `sys_qr_scene`.
2. Logged-in mobile user scans with `/auth/qr/scan`.
3. Polling side reads `/auth/qr/scene/{sceneCode}`.
4. Logged-in mobile user confirms with `/auth/qr/confirm`.
5. When approved, controller generates tokens and marks scene consumed.
6. Terminal scenes can be cleaned later from JDBC storage.

### Social Login

1. Controller selects provider by endpoint.
2. `DefaultSocialLoginService` finds matching `SocialAuthProvider`.
3. Provider resolves external identity.
4. `SocialAccountService` finds or creates a local user and binding.
5. Controller issues normal JWT tokens.

## Plugin Model

- Controller depends on `ObjectProvider<QrLoginService>` and `ObjectProvider<SocialLoginService>`.
- QR login can be disabled with `auth-module.qr-login.enabled=false`.
- Social providers are filtered by `auth-module.authentication.enabled-types`.
- Provider implementations can be overridden by defining custom `SocialAuthProvider`, `QrLoginService`, `PasswordManagementService`, or other SPI beans.
- Tenant-scoped management reads default to the caller tenant unless the caller has `SUPER_ADMIN`.

## Security Notes

- Stateless JWT authentication with refresh token rotation.
- Token blacklist is used for logout and refresh invalidation.
- Password failures increment `failed_login_attempts`.
- `locked_until` blocks further password login attempts until expiry.
- Management endpoints require `ADMIN` or `SUPER_ADMIN`.
- Management endpoints also enforce method-level permissions from the authenticated principal.
