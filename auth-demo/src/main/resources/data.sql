insert into sys_tenant (id, tenant_code, tenant_name, is_default)
values (1, 'DEFAULT', 'Default Tenant', 1)
on conflict (id) do update
set tenant_code = excluded.tenant_code,
    tenant_name = excluded.tenant_name,
    is_default = excluded.is_default;

insert into sys_group (id, tenant_id, group_code, group_name, parent_id, ancestors, is_default)
values (1, 1, 'DEFAULT', 'Default Group', null, null, 1)
on conflict (id) do update
set tenant_id = excluded.tenant_id,
    group_code = excluded.group_code,
    group_name = excluded.group_name,
    parent_id = excluded.parent_id,
    ancestors = excluded.ancestors,
    is_default = excluded.is_default;

insert into sys_user (
    id, username, display_name, status, group_id, tenant_id, register_source, password_version, deleted
)
values (
    1, 'admin', 'System Administrator', 1, 1, 1, 'BOOTSTRAP', 1, 0
)
on conflict (id) do update
set username = excluded.username,
    display_name = excluded.display_name,
    status = excluded.status,
    group_id = excluded.group_id,
    tenant_id = excluded.tenant_id,
    register_source = excluded.register_source,
    password_version = excluded.password_version,
    deleted = excluded.deleted;

insert into sys_auth (
    id, user_id, identity_type, principal_key, credential_hash, metadata_json, enabled
)
values (
    1, 1, 'PASSWORD', 'admin', '{noop}P@ssw0rd!', '{}'::jsonb, 1
)
on conflict (identity_type, principal_key) do update
set user_id = excluded.user_id,
    credential_hash = excluded.credential_hash,
    metadata_json = excluded.metadata_json,
    enabled = excluded.enabled;

insert into sys_role (
    id, tenant_id, role_code, role_name, data_scope, enabled
)
values
    (1, 1, 'ADMIN', 'Administrator', 'ALL', 1),
    (2, 1, 'USER', 'User', 'SELF', 1),
    (3, 1, 'SUPER_ADMIN', 'Super Administrator', 'ALL', 1)
on conflict (id) do update
set tenant_id = excluded.tenant_id,
    role_code = excluded.role_code,
    role_name = excluded.role_name,
    data_scope = excluded.data_scope,
    enabled = excluded.enabled;

insert into sys_permission (
    id, tenant_id, permission_code, permission_name, permission_type, enabled
)
values
    (1, 1, 'menu:system:user', 'User Menu', 'MENU', 1),
    (2, 1, 'button:system:user:create', 'Create User Button', 'BUTTON', 1),
    (3, 1, 'api:GET:/auth/me', 'Current User', 'API', 1),
    (4, 1, 'api:POST:/auth/token/refresh', 'Refresh Token', 'API', 1),
    (5, 1, 'api:GET:/auth/users', 'List Users', 'API', 1),
    (6, 1, 'api:POST:/auth/qr/scene', 'Create QR Scene', 'API', 1),
    (7, 1, 'api:GET:/auth/roles', 'List Roles', 'API', 1),
    (8, 1, 'api:GET:/auth/permissions', 'List Permissions', 'API', 1),
    (9, 1, 'api:POST:/auth/users/roles', 'Assign User Roles', 'API', 1),
    (10, 1, 'api:GET:/auth/tenants', 'List Tenants', 'API', 1),
    (11, 1, 'api:POST:/auth/tenants', 'Create Tenant', 'API', 1),
    (12, 1, 'api:GET:/auth/groups', 'List Groups', 'API', 1),
    (13, 1, 'api:POST:/auth/groups', 'Create Group', 'API', 1),
    (14, 1, 'api:POST:/auth/groups/roles', 'Assign Group Roles', 'API', 1)
on conflict (id) do update
set tenant_id = excluded.tenant_id,
    permission_code = excluded.permission_code,
    permission_name = excluded.permission_name,
    permission_type = excluded.permission_type,
    enabled = excluded.enabled;

insert into sys_user_role (id, user_id, role_id)
values (1, 1, 1)
on conflict (user_id, role_id) do nothing;

insert into sys_group_role (id, group_id, role_id)
values (1, 1, 2)
on conflict (group_id, role_id) do nothing;

insert into sys_role_permission (id, role_id, permission_id)
values
    (1, 1, 1),
    (2, 1, 2),
    (3, 1, 3),
    (4, 2, 3),
    (5, 2, 4),
    (6, 1, 5),
    (7, 1, 6),
    (8, 1, 7),
    (9, 1, 8),
    (10, 1, 9),
    (11, 1, 10),
    (12, 1, 11),
    (13, 1, 12),
    (14, 1, 13),
    (15, 1, 14)
on conflict (role_id, permission_id) do nothing;

select setval('sys_tenant_id_seq', coalesce((select max(id) from sys_tenant), 1), true);
select setval('sys_group_id_seq', coalesce((select max(id) from sys_group), 1), true);
select setval('sys_user_id_seq', coalesce((select max(id) from sys_user), 1), true);
select setval('sys_auth_id_seq', coalesce((select max(id) from sys_auth), 1), true);
select setval('sys_role_id_seq', coalesce((select max(id) from sys_role), 1), true);
select setval('sys_permission_id_seq', coalesce((select max(id) from sys_permission), 1), true);
select setval('sys_user_role_id_seq', coalesce((select max(id) from sys_user_role), 1), true);
select setval('sys_group_role_id_seq', coalesce((select max(id) from sys_group_role), 1), true);
select setval('sys_role_permission_id_seq', coalesce((select max(id) from sys_role_permission), 1), true);
