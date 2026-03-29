package org.sainm.auth.persistence

import com.fasterxml.jackson.databind.ObjectMapper
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.exception.InvalidCredentialsException
import org.sainm.auth.core.exception.PasswordValidationException
import org.sainm.auth.core.exception.UserAlreadyExistsException
import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.core.spi.AuditQueryService
import org.sainm.auth.core.spi.ChangePasswordCommand
import org.sainm.auth.core.spi.CreateGroupCommand
import org.sainm.auth.core.spi.CreateTenantCommand
import org.sainm.auth.core.spi.GroupRoleAssignmentCommand
import org.sainm.auth.core.spi.GroupSummary
import org.sainm.auth.core.spi.LoginAttemptResult
import org.sainm.auth.core.spi.LoginAttemptService
import org.sainm.auth.core.spi.LoginLogRecord
import org.sainm.auth.core.spi.OrganizationService
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.PermissionSummary
import org.sainm.auth.core.spi.PasswordManagementService
import org.sainm.auth.core.spi.ResetPasswordCommand
import org.sainm.auth.core.spi.RoleAssignmentCommand
import org.sainm.auth.core.spi.RoleSummary
import org.sainm.auth.core.spi.SecurityEventRecord
import org.sainm.auth.core.spi.SocialAccountService
import org.sainm.auth.core.spi.SocialIdentity
import org.sainm.auth.core.spi.TenantSummary
import org.sainm.auth.core.spi.TokenBlacklistService
import org.sainm.auth.core.spi.UserAdminService
import org.sainm.auth.core.spi.UserCredentialView
import org.sainm.auth.core.spi.UserLookupService
import org.sainm.auth.core.spi.UserRegistrationCommand
import org.sainm.auth.core.spi.UserRegistrationResult
import org.sainm.auth.core.spi.UserRegistrationService
import org.sainm.auth.core.spi.UserSummary
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.jdbc.support.GeneratedKeyHolder
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.security.crypto.password.PasswordEncoder
import java.sql.Statement

class JdbcUserLookupService(
    private val jdbcTemplate: JdbcTemplate
) : UserLookupService {

    override fun findById(userId: Long): UserPrincipal? =
        jdbcTemplate.query(
            """
            select id, username, display_name, status, group_id, tenant_id, locked_until, password_version
            from sys_user
            where id = ? and deleted = 0
            """.trimIndent(),
            userPrincipalRowMapper,
            userId
        ).firstOrNull()

    override fun findByPrincipal(principal: String): UserCredentialView? =
        jdbcTemplate.query(
            """
            select
                u.id,
                u.username,
                u.display_name,
                u.status,
                u.group_id,
                u.tenant_id,
                u.locked_until,
                u.password_version,
                a.credential_hash
            from sys_user u
            join sys_auth a on a.user_id = u.id
            where a.identity_type = 'PASSWORD'
              and a.principal_key = ?
              and a.enabled = 1
              and u.deleted = 0
            """.trimIndent(),
            RowMapper { rs, _ ->
                UserCredentialView(
                    principal = mapUserPrincipal(
                        rs.getLong("id"),
                        rs.getString("username"),
                        rs.getString("display_name"),
                        rs.getShort("status"),
                        rs.getNullableLong("group_id"),
                        rs.getNullableLong("tenant_id"),
                        rs.getTimestamp("locked_until")?.toInstant(),
                        rs.getInt("password_version")
                    ),
                    passwordHash = rs.getString("credential_hash")
                )
            },
            principal
        ).firstOrNull()

    private val userPrincipalRowMapper = RowMapper { rs, _ ->
        mapUserPrincipal(
            rs.getLong("id"),
            rs.getString("username"),
            rs.getString("display_name"),
            rs.getShort("status"),
            rs.getNullableLong("group_id"),
            rs.getNullableLong("tenant_id"),
            rs.getTimestamp("locked_until")?.toInstant(),
            rs.getInt("password_version")
        )
    }

    private fun mapUserPrincipal(
        id: Long,
        username: String,
        displayName: String?,
        status: Short,
        groupId: Long?,
        tenantId: Long?,
        lockedUntil: java.time.Instant?,
        passwordVersion: Int
    ): UserPrincipal =
        UserPrincipal(
            userId = id,
            username = username,
            displayName = displayName,
            status = when (status.toInt()) {
                0 -> UserStatus.DISABLED
                2 -> UserStatus.LOCKED
                else -> if (lockedUntil != null && lockedUntil.isAfter(java.time.Instant.now())) UserStatus.LOCKED else UserStatus.ENABLED
            },
            groupId = groupId,
            tenantId = tenantId,
            attributes = mapOf(
                "passwordVersion" to passwordVersion,
                "lockedUntil" to lockedUntil?.epochSecond
            )
        )
}

class JdbcLoginAttemptService(
    private val jdbcTemplate: JdbcTemplate,
    private val maxAttempts: Int,
    private val lockDurationMinutes: Long
) : LoginAttemptService {

    override fun resetAttempts(userId: Long) {
        jdbcTemplate.update(
            """
            update sys_user
            set failed_login_attempts = 0,
                locked_until = null,
                updated_at = current_timestamp
            where id = ?
            """.trimIndent(),
            userId
        )
    }

    override fun recordFailure(principal: String): LoginAttemptResult {
        val user = jdbcTemplate.queryForList(
            """
            select id, failed_login_attempts
            from sys_user
            where username = ? and deleted = 0
            limit 1
            """.trimIndent(),
            principal
        ).firstOrNull() ?: return LoginAttemptResult(false, null, null)

        val userId = (user["id"] as Number).toLong()
        val nextAttempt = ((user["failed_login_attempts"] as? Number)?.toInt() ?: 0) + 1
        return if (nextAttempt >= maxAttempts) {
            val lockedUntil = java.time.Instant.now().plusSeconds(lockDurationMinutes * 60)
            jdbcTemplate.update(
                """
                update sys_user
                set failed_login_attempts = ?,
                    locked_until = ?,
                    updated_at = current_timestamp
                where id = ?
                """.trimIndent(),
                nextAttempt,
                java.sql.Timestamp.from(lockedUntil),
                userId
            )
            LoginAttemptResult(true, 0, lockedUntil.epochSecond)
        } else {
            jdbcTemplate.update(
                """
                update sys_user
                set failed_login_attempts = ?,
                    updated_at = current_timestamp
                where id = ?
                """.trimIndent(),
                nextAttempt,
                userId
            )
            LoginAttemptResult(false, (maxAttempts - nextAttempt).coerceAtLeast(0), null)
        }
    }
}

class JdbcPasswordManagementService(
    private val jdbcTemplate: JdbcTemplate,
    private val passwordEncoder: PasswordEncoder,
    private val minLength: Int
) : PasswordManagementService {

    override fun changePassword(command: ChangePasswordCommand) {
        validateNewPassword(command.newPassword)
        val credential = jdbcTemplate.queryForList(
            """
            select a.credential_hash
            from sys_auth a
            join sys_user u on u.id = a.user_id
            where u.id = ?
              and a.identity_type = 'PASSWORD'
              and a.enabled = 1
              and u.deleted = 0
            limit 1
            """.trimIndent(),
            command.userId
        ).firstOrNull() ?: throw InvalidCredentialsException()

        val currentHash = credential["credential_hash"] as String
        if (!passwordEncoder.matches(command.oldPassword, currentHash)) {
            throw InvalidCredentialsException()
        }
        updatePassword(command.userId, command.newPassword)
    }

    override fun resetPassword(command: ResetPasswordCommand) {
        validateNewPassword(command.newPassword)
        val userId = jdbcTemplate.queryForObject(
            """
            select id
            from sys_user
            where username = ? and deleted = 0
            limit 1
            """.trimIndent(),
            Long::class.java,
            command.principal
        ) ?: throw InvalidCredentialsException()
        updatePassword(userId, command.newPassword)
    }

    private fun updatePassword(userId: Long, newPassword: String) {
        jdbcTemplate.update(
            """
            update sys_auth
            set credential_hash = ?,
                updated_at = current_timestamp
            where user_id = ?
              and identity_type = 'PASSWORD'
            """.trimIndent(),
            passwordEncoder.encode(newPassword),
            userId
        )
        jdbcTemplate.update(
            """
            update sys_user
            set password_version = password_version + 1,
                failed_login_attempts = 0,
                locked_until = null,
                updated_at = current_timestamp
            where id = ?
            """.trimIndent(),
            userId
        )
    }

    private fun validateNewPassword(password: String) {
        if (password.length < minLength || password.none(Char::isUpperCase) || password.none(Char::isDigit)) {
            throw PasswordValidationException("新密码至少 ${minLength} 位，且需包含大写字母和数字")
        }
    }
}

class JdbcPermissionService(
    private val jdbcTemplate: JdbcTemplate
) : PermissionService {

    override fun loadPermissions(userId: Long): Set<String> =
        jdbcTemplate.queryForList(
            """
            select distinct p.permission_code
            from sys_permission p
            join sys_role_permission rp on rp.permission_id = p.id
            join (
                select role_id
                from sys_user_role
                where user_id = ?
                union
                select gr.role_id
                from sys_group_role gr
                join sys_user u on u.group_id = gr.group_id
                where u.id = ?
                  and u.deleted = 0
            ) role_scope on role_scope.role_id = rp.role_id
            where p.enabled = 1
              and (p.tenant_id is null or p.tenant_id = (select tenant_id from sys_user where id = ? and deleted = 0))
            order by p.permission_code
            """.trimIndent(),
            String::class.java,
            userId,
            userId,
            userId
        ).toSet()

    override fun loadRoles(userId: Long): Set<String> =
        jdbcTemplate.queryForList(
            """
            select distinct r.role_code
            from sys_role r
            join (
                select role_id
                from sys_user_role
                where user_id = ?
                union
                select gr.role_id
                from sys_group_role gr
                join sys_user u on u.group_id = gr.group_id
                where u.id = ?
                  and u.deleted = 0
            ) role_scope on role_scope.role_id = r.id
            where r.enabled = 1
              and (r.tenant_id is null or r.tenant_id = (select tenant_id from sys_user where id = ? and deleted = 0))
            order by r.role_code
            """.trimIndent(),
            String::class.java,
            userId,
            userId,
            userId
        ).toSet()
}

class JdbcUserRegistrationService(
    private val jdbcTemplate: JdbcTemplate,
    private val passwordEncoder: PasswordEncoder
) : UserRegistrationService {

    override fun register(command: UserRegistrationCommand): UserRegistrationResult {
        assertUsernameAvailable(command.username)

        val userId = insertUser(
            username = command.username,
            displayName = command.displayName ?: command.username,
            email = command.email,
            mobile = command.mobile,
            registerSource = "SELF",
            groupId = findDefaultGroupId(),
            tenantId = findDefaultTenantId()
        )

        jdbcTemplate.update(
            """
            insert into sys_auth (user_id, identity_type, principal_key, credential_hash, metadata_json, enabled)
            values (?, 'PASSWORD', ?, ?, '{}'::jsonb, 1)
            """.trimIndent(),
            userId,
            command.username,
            passwordEncoder.encode(command.password)
        )

        val defaultRoleId = jdbcTemplate.queryForObject(
            "select id from sys_role where role_code = 'USER' limit 1",
            Long::class.java
        ) ?: error("Default USER role not found")

        jdbcTemplate.update(
            """
            insert into sys_user_role (user_id, role_id)
            select ?, ?
            where not exists (
                select 1 from sys_user_role where user_id = ? and role_id = ?
            )
            """.trimIndent(),
            userId,
            defaultRoleId,
            userId,
            defaultRoleId
        )

        return UserRegistrationResult(
            userId = userId,
            username = command.username,
            defaultRoles = setOf("USER")
        )
    }

    private fun assertUsernameAvailable(username: String) {
        val exists = jdbcTemplate.queryForObject(
            "select exists(select 1 from sys_user where username = ? and deleted = 0)",
            Boolean::class.java,
            username
        ) ?: false
        if (exists) {
            throw UserAlreadyExistsException()
        }
    }

    fun insertUser(
        username: String,
        displayName: String,
        email: String?,
        mobile: String?,
        registerSource: String,
        groupId: Long?,
        tenantId: Long?
    ): Long {
        val keyHolder = GeneratedKeyHolder()
        jdbcTemplate.update({ connection ->
            connection.prepareStatement(
                """
                insert into sys_user (
                    username, display_name, email, mobile, status, register_source, password_version, deleted, group_id, tenant_id
                ) values (?, ?, ?, ?, 1, ?, 1, 0, ?, ?)
                """.trimIndent(),
                Statement.RETURN_GENERATED_KEYS
            ).apply {
                setString(1, username)
                setString(2, displayName)
                setString(3, email)
                setString(4, mobile)
                setString(5, registerSource)
                setNullableLong(6, groupId)
                setNullableLong(7, tenantId)
            }
        }, keyHolder)

        return keyHolder.keys?.get("id")?.let { (it as Number).toLong() }
            ?: keyHolder.key?.toLong()
            ?: error("Failed to create user")
    }

    private fun findDefaultGroupId(): Long? =
        runCatching {
            jdbcTemplate.queryForObject(
                "select id from sys_group where is_default = 1 order by id limit 1",
                Long::class.java
            )
        }.getOrNull()

    private fun findDefaultTenantId(): Long? =
        runCatching {
            jdbcTemplate.queryForObject(
                "select id from sys_tenant where is_default = 1 order by id limit 1",
                Long::class.java
            )
        }.getOrNull()
}

class JdbcAuditEventPublisher(
    private val jdbcTemplate: JdbcTemplate,
    private val objectMapper: ObjectMapper
) : AuditEventPublisher {

    override fun publish(event: AuditEvent) {
        when (event.type) {
            "LOGIN_SUCCESS" -> insertLoginLog(event, "SUCCESS")
            "LOGIN_FAIL" -> {
                insertLoginLog(event, "FAIL")
                insertSecurityEvent(event)
            }
            "ACCESS_DENIED" -> insertSecurityEvent(event)
            else -> insertSecurityEvent(event)
        }
    }

    private fun insertLoginLog(event: AuditEvent, result: String) {
        jdbcTemplate.update(
            """
            insert into sys_login_log (user_id, principal, login_type, result, reason)
            values (?, ?, ?, ?, ?)
            """.trimIndent(),
            event.userId,
            event.principal,
            event.detail["loginType"] ?: "PASSWORD",
            result,
            event.detail["reason"]
        )
    }

    private fun insertSecurityEvent(event: AuditEvent) {
        jdbcTemplate.update(
            """
            insert into sys_security_event (event_type, user_id, tenant_id, detail_json, ip)
            values (?, ?, ?, cast(? as jsonb), ?)
            """.trimIndent(),
            event.type,
            event.userId,
            event.detail["tenantId"],
            objectMapper.writeValueAsString(event.detail),
            event.detail["ip"]
        )
    }
}

class JdbcAuditQueryService(
    private val jdbcTemplate: JdbcTemplate
) : AuditQueryService {

    override fun findLoginLogs(page: Int, size: Int, principal: String?, result: String?): List<LoginLogRecord> {
        val offset = ((page - 1).coerceAtLeast(0)) * size.coerceAtLeast(1)
        val whereParts = mutableListOf<String>()
        val args = mutableListOf<Any>()
        if (!principal.isNullOrBlank()) {
            whereParts += "principal = ?"
            args += principal
        }
        if (!result.isNullOrBlank()) {
            whereParts += "result = ?"
            args += result
        }
        val whereSql = if (whereParts.isEmpty()) "" else "where ${whereParts.joinToString(" and ")}"
        args += size
        args += offset
        return jdbcTemplate.query(
            """
            select id, user_id, principal, login_type, result, reason, created_at
            from sys_login_log
            $whereSql
            order by id desc
            limit ? offset ?
            """.trimIndent(),
            { rs, _ ->
                LoginLogRecord(
                    id = rs.getLong("id"),
                    userId = rs.getNullableLong("user_id"),
                    principal = rs.getString("principal"),
                    loginType = rs.getString("login_type"),
                    result = rs.getString("result"),
                    reason = rs.getString("reason"),
                    createdAt = rs.getTimestamp("created_at").toInstant().toString()
                )
            },
            *args.toTypedArray()
        )
    }

    override fun findSecurityEvents(page: Int, size: Int, eventType: String?): List<SecurityEventRecord> {
        val offset = ((page - 1).coerceAtLeast(0)) * size.coerceAtLeast(1)
        val args = mutableListOf<Any>()
        val whereSql = if (eventType.isNullOrBlank()) {
            ""
        } else {
            args += eventType
            "where event_type = ?"
        }
        args += size
        args += offset
        return jdbcTemplate.query(
            """
            select id, event_type, user_id, tenant_id, detail_json, ip, created_at
            from sys_security_event
            $whereSql
            order by id desc
            limit ? offset ?
            """.trimIndent(),
            { rs, _ ->
                SecurityEventRecord(
                    id = rs.getLong("id"),
                    eventType = rs.getString("event_type"),
                    userId = rs.getNullableLong("user_id"),
                    tenantId = rs.getNullableLong("tenant_id"),
                    detailJson = rs.getString("detail_json"),
                    ip = rs.getString("ip"),
                    createdAt = rs.getTimestamp("created_at").toInstant().toString()
                )
            },
            *args.toTypedArray()
        )
    }
}

class JdbcUserAdminService(
    private val jdbcTemplate: JdbcTemplate
) : UserAdminService {

    override fun listUsers(page: Int, size: Int, tenantId: Long?): List<UserSummary> {
        val offset = ((page - 1).coerceAtLeast(0)) * size.coerceAtLeast(1)
        val users = if (tenantId == null) {
            jdbcTemplate.queryForList(
                """
                select id, username, display_name, status, group_id, tenant_id
                from sys_user
                where deleted = 0
                order by id desc
                limit ? offset ?
                """.trimIndent(),
                size,
                offset
            )
        } else {
            jdbcTemplate.queryForList(
                """
                select id, username, display_name, status, group_id, tenant_id
                from sys_user
                where deleted = 0
                  and tenant_id = ?
                order by id desc
                limit ? offset ?
                """.trimIndent(),
                tenantId,
                size,
                offset
            )
        }

        return users.map { row ->
            val userId = (row["id"] as Number).toLong()
            UserSummary(
                userId = userId,
                username = row["username"] as String,
                displayName = row["display_name"] as String?,
                status = when ((row["status"] as Number).toInt()) {
                    0 -> "DISABLED"
                    2 -> "LOCKED"
                    else -> "ENABLED"
                },
                groupId = (row["group_id"] as Number?)?.toLong(),
                tenantId = (row["tenant_id"] as Number?)?.toLong(),
                roles = jdbcTemplate.queryForList(
                    """
                    select distinct r.role_code
                    from sys_role r
                    join (
                        select role_id
                        from sys_user_role
                        where user_id = ?
                        union
                        select gr.role_id
                        from sys_group_role gr
                        join sys_user u on u.group_id = gr.group_id
                        where u.id = ?
                    ) role_scope on role_scope.role_id = r.id
                    order by r.role_code
                    """.trimIndent(),
                    String::class.java,
                    userId,
                    userId
                ).toSet()
            )
        }
    }

    override fun listRoles(tenantId: Long?): List<RoleSummary> =
        jdbcTemplate.query(
            """
            select id, role_code, role_name, tenant_id
            from sys_role
            where enabled = 1
            ${if (tenantId == null) "" else "and tenant_id = ?"}
            order by id
            """.trimIndent(),
            { rs, _ ->
                RoleSummary(
                    roleId = rs.getLong("id"),
                    roleCode = rs.getString("role_code"),
                    roleName = rs.getString("role_name"),
                    tenantId = rs.getNullableLong("tenant_id")
                )
            },
            *listOfNotNull(tenantId).toTypedArray()
        )

    override fun listPermissions(tenantId: Long?): List<PermissionSummary> =
        jdbcTemplate.query(
            """
            select id, permission_code, permission_name, permission_type, tenant_id
            from sys_permission
            where enabled = 1
            ${if (tenantId == null) "" else "and tenant_id = ?"}
            order by id
            """.trimIndent(),
            { rs, _ ->
                PermissionSummary(
                    permissionId = rs.getLong("id"),
                    permissionCode = rs.getString("permission_code"),
                    permissionName = rs.getString("permission_name"),
                    permissionType = rs.getString("permission_type"),
                    tenantId = rs.getNullableLong("tenant_id")
                )
            },
            *listOfNotNull(tenantId).toTypedArray()
        )

    override fun assignRoles(command: RoleAssignmentCommand): Set<String> {
        jdbcTemplate.update("delete from sys_user_role where user_id = ?", command.userId)
        if (command.roleCodes.isEmpty()) {
            return emptySet()
        }

        val roleIds = jdbcTemplate.queryForList(
            """
            select id
            from sys_role
            where role_code in (${command.roleCodes.joinToString(",") { "?" }})
            """.trimIndent(),
            Long::class.java,
            *command.roleCodes.toTypedArray()
        )

        roleIds.forEach { roleId ->
            jdbcTemplate.update(
                """
                insert into sys_user_role (user_id, role_id)
                select ?, ?
                where not exists (
                    select 1 from sys_user_role where user_id = ? and role_id = ?
                )
                """.trimIndent(),
                command.userId,
                roleId,
                command.userId,
                roleId
            )
        }
        return listUsers(1, Int.MAX_VALUE, null)
            .firstOrNull { it.userId == command.userId }
            ?.roles
            .orEmpty()
    }
}

class JdbcOrganizationService(
    private val jdbcTemplate: JdbcTemplate
) : OrganizationService {

    override fun listGroups(tenantId: Long?): List<GroupSummary> =
        jdbcTemplate.query(
            """
            select id, group_code, group_name, tenant_id, parent_id, ancestors
            from sys_group
            ${if (tenantId == null) "" else "where tenant_id = ?"}
            order by id
            """.trimIndent(),
            { rs, _ ->
                val groupId = rs.getLong("id")
                GroupSummary(
                    groupId = groupId,
                    groupCode = rs.getString("group_code"),
                    groupName = rs.getString("group_name"),
                    tenantId = rs.getNullableLong("tenant_id"),
                    parentId = rs.getNullableLong("parent_id"),
                    ancestors = rs.getString("ancestors"),
                    roles = jdbcTemplate.queryForList(
                        """
                        select r.role_code
                        from sys_group_role gr
                        join sys_role r on r.id = gr.role_id
                        where gr.group_id = ?
                        order by r.role_code
                        """.trimIndent(),
                        String::class.java,
                        groupId
                    ).toSet()
                )
            },
            *listOfNotNull(tenantId).toTypedArray()
        )

    override fun createGroup(command: CreateGroupCommand): GroupSummary {
        val ancestors = resolveAncestors(command.parentId)
        val keyHolder = GeneratedKeyHolder()
        jdbcTemplate.update({ connection ->
            connection.prepareStatement(
                """
                insert into sys_group (group_code, group_name, tenant_id, parent_id, ancestors, is_default)
                values (?, ?, ?, ?, ?, 0)
                """.trimIndent(),
                Statement.RETURN_GENERATED_KEYS
            ).apply {
                setString(1, command.groupCode)
                setString(2, command.groupName)
                setNullableLong(3, command.tenantId)
                setNullableLong(4, command.parentId)
                setString(5, ancestors)
            }
        }, keyHolder)
        val groupId = keyHolder.keys?.get("id")?.let { (it as Number).toLong() }
            ?: keyHolder.key?.toLong()
            ?: error("Failed to create group")
        return GroupSummary(groupId, command.groupCode, command.groupName, command.tenantId, command.parentId, ancestors)
    }

    override fun assignGroupRoles(command: GroupRoleAssignmentCommand): Set<String> {
        jdbcTemplate.update("delete from sys_group_role where group_id = ?", command.groupId)
        if (command.roleCodes.isEmpty()) {
            return emptySet()
        }
        val roleIds = jdbcTemplate.queryForList(
            """
            select id
            from sys_role
            where role_code in (${command.roleCodes.joinToString(",") { "?" }})
            """.trimIndent(),
            Long::class.java,
            *command.roleCodes.toTypedArray()
        )
        roleIds.forEach { roleId ->
            jdbcTemplate.update(
                """
                insert into sys_group_role (group_id, role_id)
                select ?, ?
                where not exists (
                    select 1 from sys_group_role where group_id = ? and role_id = ?
                )
                """.trimIndent(),
                command.groupId,
                roleId,
                command.groupId,
                roleId
            )
        }
        return jdbcTemplate.queryForList(
            """
            select r.role_code
            from sys_group_role gr
            join sys_role r on r.id = gr.role_id
            where gr.group_id = ?
            order by r.role_code
            """.trimIndent(),
            String::class.java,
            command.groupId
        ).toSet()
    }

    override fun listTenants(tenantId: Long?): List<TenantSummary> =
        jdbcTemplate.query(
            """
            select id, tenant_code, tenant_name
            from sys_tenant
            ${if (tenantId == null) "" else "where id = ?"}
            order by id
            """.trimIndent(),
            { rs, _ ->
                TenantSummary(
                    tenantId = rs.getLong("id"),
                    tenantCode = rs.getString("tenant_code"),
                    tenantName = rs.getString("tenant_name")
                )
            },
            *listOfNotNull(tenantId).toTypedArray()
        )

    override fun createTenant(command: CreateTenantCommand): TenantSummary {
        val keyHolder = GeneratedKeyHolder()
        jdbcTemplate.update({ connection ->
            connection.prepareStatement(
                """
                insert into sys_tenant (tenant_code, tenant_name, is_default)
                values (?, ?, 0)
                """.trimIndent(),
                Statement.RETURN_GENERATED_KEYS
            ).apply {
                setString(1, command.tenantCode)
                setString(2, command.tenantName)
            }
        }, keyHolder)
        val tenantId = keyHolder.keys?.get("id")?.let { (it as Number).toLong() }
            ?: keyHolder.key?.toLong()
            ?: error("Failed to create tenant")
        return TenantSummary(tenantId, command.tenantCode, command.tenantName)
    }

    private fun resolveAncestors(parentId: Long?): String? {
        if (parentId == null) {
            return null
        }
        val parent = jdbcTemplate.queryForMap(
            "select id, ancestors from sys_group where id = ?",
            parentId
        )
        val parentAncestors = parent["ancestors"] as String?
        return listOfNotNull(parentAncestors?.takeIf { it.isNotBlank() }, parentId.toString())
            .joinToString(",")
            .ifBlank { null }
    }
}

class JdbcSocialAccountService(
    private val jdbcTemplate: JdbcTemplate,
    private val userLookupService: UserLookupService,
    private val userRegistrationService: JdbcUserRegistrationService
) : SocialAccountService {

    override fun findOrCreate(identity: SocialIdentity): UserPrincipal {
        val normalizedProvider = identity.provider.uppercase()
        val externalId = identity.externalId.trim()
        val existingUserId = try {
            jdbcTemplate.queryForObject(
                """
                select user_id
                from sys_auth
                where identity_type = ?
                  and principal_key = ?
                  and enabled = 1
                limit 1
                """.trimIndent(),
                Long::class.java,
                normalizedProvider,
                externalId
            )
        } catch (_: EmptyResultDataAccessException) {
            null
        }

        val userId = existingUserId ?: createSocialUser(identity.copy(provider = normalizedProvider, externalId = externalId))
        return userLookupService.findById(userId)
            ?: error("Social login user not found")
    }

    private fun createSocialUser(identity: SocialIdentity): Long {
        val provider = identity.provider
        val externalId = identity.externalId
        val usernamePrefix = provider.lowercase()
        val baseUsername = "${usernamePrefix}_${externalId.lowercase().replace(Regex("[^a-z0-9_]"), "_")}"
        val username = nextAvailableUsername(baseUsername)
        val displayName = identity.displayName ?: "${provider.lowercase().replaceFirstChar(Char::titlecase)} User"
        val userId = userRegistrationService.insertUser(
            username = username,
            displayName = displayName,
            email = identity.email,
            mobile = null,
            registerSource = provider,
            groupId = null,
            tenantId = null
        )

        jdbcTemplate.update(
            """
            insert into sys_auth (user_id, identity_type, principal_key, credential_hash, metadata_json, enabled)
            values (?, ?, ?, null, '{}'::jsonb, 1)
            """.trimIndent(),
            userId,
            provider,
            externalId
        )

        val defaultRoleId = jdbcTemplate.queryForObject(
            "select id from sys_role where role_code = 'USER' limit 1",
            Long::class.java
        ) ?: error("Default USER role not found")
        jdbcTemplate.update(
            """
            insert into sys_user_role (user_id, role_id)
            select ?, ?
            where not exists (
                select 1 from sys_user_role where user_id = ? and role_id = ?
            )
            """.trimIndent(),
            userId,
            defaultRoleId,
            userId,
            defaultRoleId
        )
        return userId
    }

    private fun nextAvailableUsername(baseUsername: String): String {
        var candidate = baseUsername.take(48)
        var index = 1
        while (jdbcTemplate.queryForObject(
                "select exists(select 1 from sys_user where username = ? and deleted = 0)",
                Boolean::class.java,
                candidate
            ) == true) {
            candidate = "${baseUsername.take(40)}_$index"
            index++
        }
        return candidate
    }
}

class JdbcTokenBlacklistService(
    private val jdbcTemplate: JdbcTemplate
) : TokenBlacklistService {

    override fun blacklist(jti: String, userId: Long, expireAtEpochSecond: Long) {
        jdbcTemplate.update(
            """
            insert into sys_token_blacklist (jti, user_id, expire_at)
            values (?, ?, to_timestamp(?))
            on conflict (jti) do update
            set user_id = excluded.user_id,
                expire_at = excluded.expire_at
            """.trimIndent(),
            jti,
            userId,
            expireAtEpochSecond
        )
    }

    override fun isBlacklisted(jti: String): Boolean =
        jdbcTemplate.queryForObject(
            """
            select exists(
                select 1
                from sys_token_blacklist
                where jti = ?
                  and expire_at > current_timestamp
            )
            """.trimIndent(),
            Boolean::class.java,
            jti
        ) ?: false
}

private fun java.sql.ResultSet.getNullableLong(columnLabel: String): Long? =
    getObject(columnLabel)?.let { (it as Number).toLong() }

private fun java.sql.PreparedStatement.setNullableLong(index: Int, value: Long?) {
    if (value == null) {
        setNull(index, java.sql.Types.BIGINT)
    } else {
        setLong(index, value)
    }
}
