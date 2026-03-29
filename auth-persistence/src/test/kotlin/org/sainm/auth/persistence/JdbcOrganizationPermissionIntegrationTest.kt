package org.sainm.auth.persistence

import org.sainm.auth.core.spi.CreateGroupCommand
import org.sainm.auth.core.spi.GroupRoleAssignmentCommand
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JdbcOrganizationPermissionIntegrationTest {

    private val dataSource = DriverManagerDataSource().apply {
        setDriverClassName("org.h2.Driver")
        url = "jdbc:h2:mem:auth_org_perm_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1"
        username = "sa"
        password = ""
    }
    private val jdbcTemplate = JdbcTemplate(dataSource)

    init {
        jdbcTemplate.execute("drop table if exists sys_role_permission")
        jdbcTemplate.execute("drop table if exists sys_permission")
        jdbcTemplate.execute("drop table if exists sys_user_role")
        jdbcTemplate.execute("drop table if exists sys_group_role")
        jdbcTemplate.execute("drop table if exists sys_role")
        jdbcTemplate.execute("drop table if exists sys_user")
        jdbcTemplate.execute("drop table if exists sys_group")
        jdbcTemplate.execute("drop table if exists sys_tenant")
        jdbcTemplate.execute(
            """
            create table sys_tenant (
                id bigserial primary key,
                tenant_code varchar(64) not null,
                tenant_name varchar(128) not null
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_group (
                id bigserial primary key,
                tenant_id bigint,
                group_code varchar(64) not null,
                group_name varchar(128) not null,
                parent_id bigint,
                ancestors varchar(512),
                is_default smallint not null default 0
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_user (
                id bigserial primary key,
                username varchar(64) not null,
                display_name varchar(128),
                status smallint not null default 1,
                group_id bigint,
                tenant_id bigint,
                deleted smallint not null default 0
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_role (
                id bigserial primary key,
                tenant_id bigint,
                role_code varchar(64) not null,
                role_name varchar(128) not null,
                enabled smallint not null default 1
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_permission (
                id bigserial primary key,
                tenant_id bigint,
                permission_code varchar(128) not null,
                permission_name varchar(128) not null,
                permission_type varchar(32) not null,
                enabled smallint not null default 1
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_user_role (
                id bigserial primary key,
                user_id bigint not null,
                role_id bigint not null
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_group_role (
                id bigserial primary key,
                group_id bigint not null,
                role_id bigint not null,
                constraint uk_sys_group_role unique (group_id, role_id)
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_role_permission (
                id bigserial primary key,
                role_id bigint not null,
                permission_id bigint not null
            )
            """.trimIndent()
        )
    }

    @BeforeTest
    fun resetData() {
        listOf(
            "sys_role_permission",
            "sys_user_role",
            "sys_group_role",
            "sys_permission",
            "sys_role",
            "sys_user",
            "sys_group",
            "sys_tenant"
        ).forEach { jdbcTemplate.update("delete from $it") }
    }

    @Test
    fun `permission service includes inherited group roles within tenant`() {
        seedTenantAndGroup()
        jdbcTemplate.update("insert into sys_user (id, username, display_name, status, group_id, tenant_id, deleted) values (1, 'alice', 'Alice', 1, 1, 1, 0)")
        jdbcTemplate.update("insert into sys_role (id, tenant_id, role_code, role_name, enabled) values (1, 1, 'GROUP_ADMIN', 'Group Admin', 1)")
        jdbcTemplate.update("insert into sys_permission (id, tenant_id, permission_code, permission_name, permission_type, enabled) values (1, 1, 'api:GET:/auth/groups', 'List Groups', 'API', 1)")
        jdbcTemplate.update("insert into sys_group_role (group_id, role_id) values (1, 1)")
        jdbcTemplate.update("insert into sys_role_permission (role_id, permission_id) values (1, 1)")

        val permissionService = JdbcPermissionService(jdbcTemplate)

        assertEquals(setOf("GROUP_ADMIN"), permissionService.loadRoles(1))
        assertEquals(setOf("api:GET:/auth/groups"), permissionService.loadPermissions(1))
    }

    @Test
    fun `organization service creates tree and assigns group roles`() {
        seedTenantAndGroup()
        jdbcTemplate.update("insert into sys_role (id, tenant_id, role_code, role_name, enabled) values (2, 1, 'REVIEWER', 'Reviewer', 1)")
        val service = JdbcOrganizationService(jdbcTemplate)

        val child = service.createGroup(CreateGroupCommand("CHILD", "Child Group", 1, 1))
        val assigned = service.assignGroupRoles(GroupRoleAssignmentCommand(child.groupId, setOf("REVIEWER")))
        val groups = service.listGroups(1)
        val loadedChild = groups.first { it.groupId == child.groupId }

        assertEquals("1", loadedChild.ancestors)
        assertEquals(1L, loadedChild.parentId)
        assertEquals(setOf("REVIEWER"), assigned)
        assertTrue("REVIEWER" in loadedChild.roles)
    }

    private fun seedTenantAndGroup() {
        jdbcTemplate.update("insert into sys_tenant (tenant_code, tenant_name) values ('DEFAULT', 'Default')")
        jdbcTemplate.update(
            "insert into sys_group (tenant_id, group_code, group_name, parent_id, ancestors, is_default) values (1, 'ROOT', 'Root Group', null, null, 1)"
        )
    }
}
