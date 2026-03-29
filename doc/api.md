# API

Base path: `/auth`

Common response:

```json
{
  "code": "0",
  "message": "OK",
  "data": {}
}
```

## Authentication

`POST /auth/login/password`

```json
{
  "principal": "admin",
  "password": "P@ssw0rd!"
}
```

`POST /auth/token/refresh`

```json
{
  "refreshToken": "jwt-refresh-token"
}
```

`POST /auth/logout`

```json
{
  "refreshToken": "jwt-refresh-token"
}
```

`GET /auth/me`

Returns current authenticated user, roles, and permissions.

## Password

`POST /auth/password/change`

Requires login.

```json
{
  "oldPassword": "P@ssw0rd!",
  "newPassword": "NewPass9"
}
```

`POST /auth/password/reset`

Requires `ADMIN` or `SUPER_ADMIN`.

```json
{
  "principal": "alice",
  "newPassword": "ResetPass9"
}
```

## Registration

`POST /auth/register`

```json
{
  "username": "alice",
  "password": "P@ssw0rd!",
  "email": "alice@example.com",
  "mobile": "13800138000",
  "displayName": "Alice"
}
```

## QR Login

`POST /auth/qr/scene`

Creates a pending QR scene.

`GET /auth/qr/scene/{sceneCode}`

Polls QR scene status. When consumed, returns tokens.

`POST /auth/qr/scan`

Requires login.

```json
{
  "sceneCode": "scene-code"
}
```

`POST /auth/qr/confirm`

Requires login and confirms a scanned QR scene.

```json
{
  "sceneCode": "scene-code"
}
```

`POST /auth/qr/cancel`

Requires login and cancels a pending or scanned scene.

```json
{
  "sceneCode": "scene-code"
}
```

## Social Login

Google supports a stable real-login endpoint and keeps a mock endpoint for local demo use.

`POST /auth/social/google`

When `auth-module.social.google.enabled=true`, `authCode` should contain a Google ID token issued for the configured client ID.

```json
{
  "authCode": "google-id-token"
}
```

`POST /auth/social/google/mock`

```json
{
  "authCode": "google-demo-code"
}
```

`POST /auth/social/wechat`

When `auth-module.social.wechat.enabled=true`, `authCode` should contain the WeChat OAuth code that your frontend received.

```json
{
  "authCode": "wechat-oauth-code"
}
```

`POST /auth/social/wechat/mock`

```json
{
  "authCode": "wechat-demo-code"
}
```

## Management

`GET /auth/users?page=1&size=20`

Optional:

- `tenantId`, only honored as-is for `SUPER_ADMIN`

`GET /auth/roles`

Optional:

- `tenantId`, only honored as-is for `SUPER_ADMIN`

`GET /auth/permissions`

Optional:

- `tenantId`, only honored as-is for `SUPER_ADMIN`

`POST /auth/users/{userId}/roles`

```json
{
  "roleCodes": ["ADMIN", "USER"]
}
```

`POST /auth/groups/{groupId}/roles`

```json
{
  "roleCodes": ["USER"]
}
```

`GET /auth/tenants`

Optional:

- `tenantId`, only honored as-is for `SUPER_ADMIN`

`POST /auth/tenants`

```json
{
  "tenantCode": "TENANT_A",
  "tenantName": "Tenant A"
}
```

`GET /auth/groups`

Optional:

- `tenantId`, only honored as-is for `SUPER_ADMIN`

`POST /auth/groups`

```json
{
  "groupCode": "GROUP_A",
  "groupName": "Group A",
  "tenantId": 1,
  "parentId": 1
}
```

## Audit

`GET /auth/login-logs?page=1&size=20&principal=admin&result=SUCCESS`

`GET /auth/security-events?page=1&size=20&eventType=QR_CONFIRMED`
