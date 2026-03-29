insert into sys_tenant (id, tenant_code, tenant_name, is_default) values (1, 'DEFAULT', 'Default Tenant', 1);
insert into sys_group (id, tenant_id, group_code, group_name, parent_id, ancestors, is_default) values (1, 1, 'DEFAULT', 'Default Group', null, null, 1);

insert into sys_user (
    id, username, display_name, email, mobile, status, group_id, tenant_id, register_source, password_version, failed_login_attempts, deleted
) values (
    1, 'admin', 'System Administrator', 'admin@example.test', '13800000000', 1, 1, 1, 'BOOTSTRAP', 1, 0, 0
);

insert into sys_auth (
    id, user_id, identity_type, principal_key, credential_hash, metadata_json, enabled
) values (
    1, 1, 'PASSWORD', 'admin', '{noop}P@ssw0rd!', '{}', 1
);

insert into sys_role (id, tenant_id, role_code, role_name, data_scope, enabled) values
    (1, 1, 'ADMIN', 'Administrator', 'ALL', 1),
    (2, 1, 'USER', 'User', 'SELF', 1),
    (3, 1, 'SUPER_ADMIN', 'Super Administrator', 'ALL', 1);

insert into sys_permission (id, tenant_id, permission_code, permission_name, permission_type, enabled) values
    (1, 1, 'api:GET:/auth/me', 'Current User', 'API', 1),
    (2, 1, 'api:GET:/auth/users', 'List Users', 'API', 1),
    (3, 1, 'api:GET:/auth/roles', 'List Roles', 'API', 1),
    (4, 1, 'api:GET:/auth/permissions', 'List Permissions', 'API', 1),
    (5, 1, 'api:GET:/auth/groups', 'List Groups', 'API', 1),
    (6, 1, 'api:GET:/auth/tenants', 'List Tenants', 'API', 1),
    (7, 1, 'api:POST:/auth/groups', 'Create Group', 'API', 1),
    (8, 1, 'api:POST:/auth/tenants', 'Create Tenant', 'API', 1),
    (9, 1, 'api:POST:/auth/users/roles', 'Assign User Roles', 'API', 1),
    (10, 1, 'api:POST:/auth/groups/roles', 'Assign Group Roles', 'API', 1);

insert into sys_user_role (id, user_id, role_id) values
    (1, 1, 1);

insert into sys_group_role (id, group_id, role_id) values
    (1, 1, 2);

insert into sys_role_permission (id, role_id, permission_id) values
    (1, 1, 1),
    (2, 1, 2),
    (3, 1, 3),
    (4, 1, 4),
    (5, 1, 5),
    (6, 1, 6),
    (7, 1, 7),
    (8, 1, 8),
    (9, 1, 9),
    (10, 1, 10),
    (11, 2, 1);
