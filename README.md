# auth-starter

`auth-starter` is a Spring Boot authentication and authorization starter built with Kotlin, Spring Security, and JDBC.

Current repository state:

- multi-module starter structure
- JWT access and refresh token flow
- password login, register, logout, refresh
- password change and admin reset
- login failure lock strategy
- login log and security event audit
- QR login first version
- configurable Google and WeChat social login with mock fallbacks
- starter auto-configuration and demo app

## Modules

- `auth-core`: domain and SPI
- `auth-security`: controller, JWT, filters, handlers
- `auth-persistence`: JDBC persistence defaults
- `auth-qr`: QR login implementation
- `auth-social-google`: Google ID token provider and mock Google provider
- `auth-social-wechat`: WeChat code-exchange provider and mock fallback
- `auth-audit`: fallback logging audit
- `auth-autoconfigure`: Spring Boot auto-configuration
- `auth-spring-boot-starter`: starter artifact
- `auth-demo`: runnable sample app

## Quick Start

Requirements:

- JDK 21
- PostgreSQL

The demo currently uses:

- database: `auth_starter`
- username: `auth_starter_app`
- password: `AuthStarter@2026`

Run:

```powershell
.\gradlew.bat --no-daemon build
.\gradlew.bat :auth-demo:bootJar
java -jar auth-demo\build\libs\auth-demo-0.1.0-SNAPSHOT.jar
```

Demo config is in [`auth-demo/src/main/resources/application.yml`](/d:/source/auth-starter/auth-demo/src/main/resources/application.yml).

## Starter Configuration

Main prefix:

```yaml
auth-module:
  enabled: true
  organization:
    mode: GROUP
    tenant-enabled: true
  authentication:
    enabled-types:
      - PASSWORD
      - GOOGLE
      - WECHAT
  social:
    google:
      enabled: false
      client-id: your-google-client-id.apps.googleusercontent.com
    wechat:
      enabled: false
      app-id: your-wechat-app-id
      app-secret: your-wechat-app-secret
  qr-login:
    enabled: true
    ttl-seconds: 180
  security:
    jwt:
      secret: change-me-change-me-change-me-change-me
      issuer: auth-module
      access-token-expire-minutes: 30
      refresh-token-expire-days: 7
    password:
      encoder: argon2
      min-length: 8
    lock-strategy:
      max-attempts: 5
      lock-duration-minutes: 30
  audit:
    enabled: true
```

## Error Messages

- the starter ships with English default messages only
- authentication, validation, QR, JWT, and common social-login errors resolve through Spring `MessageSource`
- host applications can override the default messages by providing the same message keys in their own resource bundles
- the default bundle lives in [`auth-security/src/main/resources/messages.properties`](/d:/source/auth-starter/auth-security/src/main/resources/messages.properties)

## Current Behavior

- changing or resetting password increments `password_version`
- old tokens are rejected after password changes
- logout blacklists access and refresh tokens
- refresh now parses a refresh token once before issuing the next token pair
- password-version checks use a short in-memory cache to reduce repeated lookups
- password failures can lock the account
- QR login supports `PENDING`, `SCANNED`, `APPROVED`, `CANCELED`, `EXPIRED`, `CONSUMED`
- QR flow endpoints include `scan`, `confirm`, and `cancel`
- expired QR scenes can be cleaned up from JDBC storage
- group roles can inherit permissions to users in the same group
- user and group management queries batch-load role assignments instead of using per-row lookups
- role assignment writes use batch SQL and registration-style multi-table writes are transactional
- tenant-scoped management queries default to the caller tenant unless the caller is `SUPER_ADMIN`
- Google can run in real ID-token verification mode when `auth-module.social.google.enabled=true`
- `/auth/social/google` is the stable Google login endpoint, while `/auth/social/google/mock` remains available for demo use
- WeChat can run in real code-exchange mode when `auth-module.social.wechat.enabled=true`
- `/auth/social/wechat` is the stable WeChat login endpoint, while `/auth/social/wechat/mock` remains available for demo use
- management APIs now also enforce method-level permissions
- `401` and `403` responses use the same `ApiResponse` JSON envelope as controller exceptions
- access-denied events are audited for both filter-level and method-level authorization failures
- social login is provider-based and can be filtered by configuration
- demo tests include an H2-backed integration path and a PostgreSQL Testcontainers path
- PostgreSQL container tests automatically skip when Docker is unavailable

## Publishing

- non-demo modules now include `maven-publish` metadata and publication configuration
- replace the placeholder SCM/developer metadata in [`gradle.properties`](/d:/source/auth-starter/gradle.properties) before a real release
- local publication is verified with `publishToMavenLocal`

## Docs

- [`doc/api.md`](/d:/source/auth-starter/doc/api.md)
- [`doc/architecture.md`](/d:/source/auth-starter/doc/architecture.md)
- [`doc/erd.md`](/d:/source/auth-starter/doc/erd.md)
- [`doc/roadmap.md`](/d:/source/auth-starter/doc/roadmap.md)
- [`doc/release.md`](/d:/source/auth-starter/doc/release.md)
- [`doc/schema-postgresql.sql`](/d:/source/auth-starter/doc/schema-postgresql.sql)
- [`doc/auth-starter-dev-kickoff.md`](/d:/source/auth-starter/doc/auth-starter-dev-kickoff.md)

## What Is Still Next

- real Google OAuth integration
- richer WeChat profile enrichment after code exchange
- Redis-backed QR concurrency control
- tenant isolation context and deeper permission strategy
- publish-ready starter documentation and release flow
