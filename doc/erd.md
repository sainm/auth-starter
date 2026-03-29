# ERD

## Core Identity

- `sys_user`
  - basic profile
  - `group_id`
  - `tenant_id`
  - `password_version`
  - `failed_login_attempts`
  - `locked_until`

- `sys_auth`
  - identity source binding
  - `identity_type`
  - `principal_key`
  - `credential_hash`

Relationship:

- `sys_auth.user_id -> sys_user.id`

## Authorization

- `sys_role`
- `sys_permission`
- `sys_user_role`
- `sys_group_role`
- `sys_role_permission`

Relationships:

- `sys_user_role.user_id -> sys_user.id`
- `sys_user_role.role_id -> sys_role.id`
- `sys_group_role.group_id -> sys_group.id`
- `sys_group_role.role_id -> sys_role.id`
- `sys_role_permission.role_id -> sys_role.id`
- `sys_role_permission.permission_id -> sys_permission.id`

## Organization

- `sys_tenant`
- `sys_group`

Logical relationships:

- `sys_group.tenant_id -> sys_tenant.id`
- `sys_group.parent_id -> sys_group.id`
- `sys_user.tenant_id -> sys_tenant.id`
- `sys_user.group_id -> sys_group.id`
- `sys_group.ancestors`: materialized lineage path for group tree queries

## Audit And Session Control

- `sys_login_log`
- `sys_security_event`
- `sys_token_blacklist`
- `sys_qr_scene`

Usage:

- `sys_login_log`: login success/fail trail.
- `sys_security_event`: access denied, account locked, and other security events.
- `sys_token_blacklist`: invalidated JWT `jti`.
- `sys_qr_scene`: pending, scanned, approved, canceled, expired, and consumed QR login scenes.
