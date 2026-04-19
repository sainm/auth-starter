# auth-starter

`auth-starter` is a Kotlin-based Spring Boot authentication and authorization starter. It provides JWT auth, session management, admin APIs, audit, QR login, social login providers, and reusable device-governance APIs.

## Requirements

- JDK 21
- PostgreSQL

## Repository Modules

- `auth-core`: domain models and SPI contracts
- `auth-security`: HTTP APIs, filters, JWT, handlers
- `auth-persistence`: JDBC persistence defaults
- `auth-qr`: QR login implementation
- `auth-social-google`: Google provider and mock fallback
- `auth-social-wechat`: WeChat provider and mock fallback
- `auth-audit`: default audit publisher
- `auth-autoconfigure`: starter auto-configuration
- `auth-spring-boot-starter`: starter artifact
- `auth-demo`: runnable demo application

## Quick Start

The demo application defaults to:

- database: `auth_starter`
- username: `auth_starter_app`
- password: `PleaseChangeThisPassword`

```powershell
.\gradlew.bat --no-daemon build
.\gradlew.bat :auth-demo:bootJar
java -jar auth-demo\build\libs\auth-demo-0.1.0-SNAPSHOT.jar
```

Demo config: [auth-demo/src/main/resources/application.yml](/D:/source/auth-starter/auth-demo/src/main/resources/application.yml)

## Core Configuration

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
    transport: http-polling
  performance:
    virtual-threads:
      enabled: false
      auth-executor-enabled: false
      qr-listener-enabled: false
  audit:
    enabled: true
    record-success-logins: true
    record-failed-logins: true
    record-access-denied: true
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
      ip-max-attempts: 20
      captcha-threshold: 3
  device-governance:
    enabled: true
    device-stale-days: 30
    session-stale-days: 30
    required-push-token-device-types:
      - ANDROID
      - IOS
```

## Device Governance

`auth-starter` exposes reusable device-governance APIs, but the device endpoints are only registered when the host application provides a `DeviceGovernanceService` bean.

Endpoints:

- `GET /auth/me/devices`
- `POST /auth/me/devices`
- `POST /auth/me/devices/{deviceId}/deactivate`
- `GET /auth/users/{userId}/devices`
- `POST /auth/users/{userId}/devices/{deviceId}/deactivate`

This keeps the starter generic while letting host applications decide how device profiles, push tokens, and linked auth sessions are stored.

## Current Behavior

- password change and admin reset revoke recorded sessions
- bearer requests update session activity with in-memory throttling and stale-entry pruning
- login and session records support stable `deviceId`
- admins can inspect and revoke user sessions
- access-denied events are audited
- Google and WeChat logins can run in real or mock mode
- QR login supports scene lifecycle and cleanup
- method-level authorization and tenant-scoped management are enabled

## Error Messages

- the starter ships with English default messages
- host applications can override keys in their own `MessageSource`
- default messages live in [auth-security/src/main/resources/messages.properties](/D:/source/auth-starter/auth-security/src/main/resources/messages.properties)

## Docs

- [doc/api.md](/D:/source/auth-starter/doc/api.md)
- [doc/architecture.md](/D:/source/auth-starter/doc/architecture.md)
- [doc/erd.md](/D:/source/auth-starter/doc/erd.md)
- [doc/roadmap.md](/D:/source/auth-starter/doc/roadmap.md)
- [doc/release.md](/D:/source/auth-starter/doc/release.md)
- [doc/schema-postgresql.sql](/D:/source/auth-starter/doc/schema-postgresql.sql)
- [doc/auth-starter-dev-kickoff.md](/D:/source/auth-starter/doc/auth-starter-dev-kickoff.md)
