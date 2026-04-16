create table if not exists sys_user (
    id bigserial primary key,
    username varchar(64) not null,
    nickname varchar(128),
    display_name varchar(128),
    email varchar(128),
    mobile varchar(32),
    avatar_url varchar(512),
    status smallint not null default 1,
    group_id bigint,
    tenant_id bigint,
    register_source varchar(32),
    password_version integer not null default 1,
    failed_login_attempts integer not null default 0,
    last_login_at timestamp(3),
    locked_until timestamp(3),
    deleted smallint not null default 0,
    created_at timestamp(3) not null default current_timestamp,
    updated_at timestamp(3) not null default current_timestamp
);

create unique index if not exists uk_sys_user_username on sys_user (username);
create unique index if not exists uk_sys_user_email on sys_user (email);
create unique index if not exists uk_sys_user_mobile on sys_user (mobile);
alter table if exists sys_user add column if not exists failed_login_attempts integer not null default 0;
alter table if exists sys_user add column if not exists password_version integer not null default 1;
alter table if exists sys_user add column if not exists locked_until timestamp(3);

create table if not exists sys_auth (
    id bigserial primary key,
    user_id bigint not null,
    identity_type varchar(32) not null,
    principal_key varchar(191) not null,
    credential_hash varchar(255),
    metadata_json jsonb,
    enabled smallint not null default 1,
    created_at timestamp(3) not null default current_timestamp,
    updated_at timestamp(3) not null default current_timestamp,
    constraint fk_sys_auth_user_id foreign key (user_id) references sys_user(id)
);

create unique index if not exists uk_sys_auth_identity_principal on sys_auth (identity_type, principal_key);
create index if not exists idx_sys_auth_user_id on sys_auth (user_id);

create table if not exists sys_tenant (
    id bigserial primary key,
    tenant_code varchar(64) not null,
    tenant_name varchar(128) not null,
    is_default smallint not null default 0,
    created_at timestamp(3) not null default current_timestamp,
    updated_at timestamp(3) not null default current_timestamp
);

create unique index if not exists uk_sys_tenant_code on sys_tenant (tenant_code);

create table if not exists sys_group (
    id bigserial primary key,
    tenant_id bigint,
    group_code varchar(64) not null,
    group_name varchar(128) not null,
    parent_id bigint,
    ancestors varchar(512),
    is_default smallint not null default 0,
    created_at timestamp(3) not null default current_timestamp,
    updated_at timestamp(3) not null default current_timestamp
);

create unique index if not exists uk_sys_group_code on sys_group (group_code);
create index if not exists idx_sys_group_parent_id on sys_group (parent_id);
alter table if exists sys_group add column if not exists parent_id bigint;
alter table if exists sys_group add column if not exists ancestors varchar(512);

create table if not exists sys_role (
    id bigserial primary key,
    tenant_id bigint,
    role_code varchar(64) not null,
    role_name varchar(128) not null,
    data_scope varchar(32) not null default 'SELF',
    enabled smallint not null default 1,
    created_at timestamp(3) not null default current_timestamp,
    updated_at timestamp(3) not null default current_timestamp
);

create unique index if not exists uk_sys_role_tenant_code on sys_role (tenant_id, role_code);

create table if not exists sys_permission (
    id bigserial primary key,
    tenant_id bigint,
    permission_code varchar(128) not null,
    permission_name varchar(128) not null,
    permission_type varchar(32) not null,
    parent_id bigint,
    path varchar(255),
    http_method varchar(16),
    resource_pattern varchar(255),
    enabled smallint not null default 1,
    created_at timestamp(3) not null default current_timestamp,
    updated_at timestamp(3) not null default current_timestamp
);

create unique index if not exists uk_sys_perm_tenant_code on sys_permission (tenant_id, permission_code);

create table if not exists sys_user_role (
    id bigserial primary key,
    user_id bigint not null,
    role_id bigint not null,
    created_at timestamp(3) not null default current_timestamp,
    constraint fk_sys_user_role_user_id foreign key (user_id) references sys_user(id),
    constraint fk_sys_user_role_role_id foreign key (role_id) references sys_role(id)
);

create unique index if not exists uk_sys_user_role on sys_user_role (user_id, role_id);

create table if not exists sys_group_role (
    id bigserial primary key,
    group_id bigint not null,
    role_id bigint not null,
    created_at timestamp(3) not null default current_timestamp,
    constraint fk_sys_group_role_group_id foreign key (group_id) references sys_group(id),
    constraint fk_sys_group_role_role_id foreign key (role_id) references sys_role(id)
);

create unique index if not exists uk_sys_group_role on sys_group_role (group_id, role_id);

create table if not exists sys_role_permission (
    id bigserial primary key,
    role_id bigint not null,
    permission_id bigint not null,
    created_at timestamp(3) not null default current_timestamp,
    constraint fk_sys_role_permission_role_id foreign key (role_id) references sys_role(id),
    constraint fk_sys_role_permission_permission_id foreign key (permission_id) references sys_permission(id)
);

create unique index if not exists uk_sys_role_permission on sys_role_permission (role_id, permission_id);

create table if not exists sys_login_log (
    id bigserial primary key,
    user_id bigint,
    principal varchar(191),
    login_type varchar(32) not null,
    result varchar(32) not null,
    ip varchar(64),
    user_agent varchar(512),
    location varchar(255),
    reason varchar(255),
    created_at timestamp(3) not null default current_timestamp
);

create index if not exists idx_sys_login_log_user_id on sys_login_log (user_id);
create index if not exists idx_sys_login_log_created_at on sys_login_log (created_at);

create table if not exists sys_security_event (
    id bigserial primary key,
    event_type varchar(64) not null,
    user_id bigint,
    tenant_id bigint,
    detail_json jsonb,
    ip varchar(64),
    created_at timestamp(3) not null default current_timestamp
);

create index if not exists idx_sys_security_event_type on sys_security_event (event_type);
create index if not exists idx_sys_security_event_created_at on sys_security_event (created_at);

create table if not exists sys_token_blacklist (
    id bigserial primary key,
    jti varchar(128) not null,
    user_id bigint not null,
    expire_at timestamp(3) not null,
    created_at timestamp(3) not null default current_timestamp
);

create unique index if not exists uk_sys_token_blacklist_jti on sys_token_blacklist (jti);
create index if not exists idx_sys_token_blacklist_expire_at on sys_token_blacklist (expire_at);

create table if not exists sys_user_session_policy (
    id bigserial primary key,
    user_id bigint not null,
    policy_code varchar(32) not null,
    created_at timestamp(3) not null default current_timestamp,
    updated_at timestamp(3) not null default current_timestamp,
    constraint uk_sys_user_session_policy_user unique (user_id),
    constraint fk_sys_user_session_policy_user_id foreign key (user_id) references sys_user(id)
);

create table if not exists sys_user_session (
    id bigserial primary key,
    session_id varchar(64) not null,
    user_id bigint not null,
    username varchar(64) not null,
    tenant_id bigint,
    client_id varchar(128),
    device_type varchar(32),
    device_name varchar(128),
    user_agent varchar(512),
    ip varchar(64),
    status varchar(32) not null default 'ACTIVE',
    last_seen_at timestamp(3),
    access_expire_at timestamp(3),
    refresh_expire_at timestamp(3),
    revoked_at timestamp(3),
    revoke_reason varchar(64),
    created_at timestamp(3) not null default current_timestamp,
    updated_at timestamp(3) not null default current_timestamp,
    constraint uk_sys_user_session_sid unique (session_id),
    constraint fk_sys_user_session_user_id foreign key (user_id) references sys_user(id)
);

create index if not exists idx_sys_user_session_user_status on sys_user_session (user_id, status);
create index if not exists idx_sys_user_session_refresh_expire_at on sys_user_session (refresh_expire_at);
create index if not exists idx_sys_user_session_updated_at on sys_user_session (updated_at desc);

create table if not exists sys_qr_scene (
    id bigserial primary key,
    scene_code varchar(64) not null,
    status varchar(32) not null,
    scanned_user_id bigint,
    scanned_at timestamp(3),
    approved_user_id bigint,
    approved_at timestamp(3),
    consumed_at timestamp(3),
    expire_at timestamp(3) not null,
    created_at timestamp(3) not null default current_timestamp
);

create unique index if not exists uk_sys_qr_scene_code on sys_qr_scene (scene_code);
create index if not exists idx_sys_qr_scene_status on sys_qr_scene (status);
create index if not exists idx_sys_qr_scene_expire_at on sys_qr_scene (expire_at);
alter table if exists sys_qr_scene add column if not exists scanned_user_id bigint;
alter table if exists sys_qr_scene add column if not exists scanned_at timestamp(3);
