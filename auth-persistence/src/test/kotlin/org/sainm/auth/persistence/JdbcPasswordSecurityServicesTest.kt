package org.sainm.auth.persistence

import org.sainm.auth.core.exception.PasswordValidationException
import org.sainm.auth.core.spi.ChangePasswordCommand
import org.sainm.auth.core.spi.ResetPasswordCommand
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JdbcPasswordSecurityServicesTest {

    private val dataSource = DriverManagerDataSource().apply {
        setDriverClassName("org.h2.Driver")
        url = "jdbc:h2:mem:auth_persistence_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1"
        username = "sa"
        password = ""
    }
    private val jdbcTemplate = JdbcTemplate(dataSource)
    private val passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

    init {
        jdbcTemplate.execute("drop table if exists sys_user_session")
        jdbcTemplate.execute("drop table if exists sys_auth")
        jdbcTemplate.execute("drop table if exists sys_user")
        jdbcTemplate.execute(
            """
            create table sys_user (
                id bigserial primary key,
                username varchar(64) not null,
                display_name varchar(128),
                status smallint not null default 1,
                group_id bigint,
                tenant_id bigint,
                register_source varchar(32),
                password_version integer not null default 1,
                failed_login_attempts integer not null default 0,
                locked_until timestamp,
                deleted smallint not null default 0,
                updated_at timestamp default current_timestamp
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_user_session (
                session_id varchar(64) primary key,
                user_id bigint not null,
                username varchar(64) not null,
                tenant_id bigint,
                client_id varchar(128),
                device_id varchar(128),
                device_type varchar(32),
                device_name varchar(128),
                user_agent varchar(512),
                ip varchar(64),
                status varchar(16) not null,
                last_seen_at timestamp,
                access_expire_at timestamp,
                refresh_expire_at timestamp,
                created_at timestamp default current_timestamp,
                updated_at timestamp default current_timestamp,
                revoked_at timestamp,
                revoke_reason varchar(64)
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_auth (
                id bigserial primary key,
                user_id bigint not null,
                identity_type varchar(32) not null,
                principal_key varchar(191) not null,
                credential_hash varchar(255),
                enabled smallint not null default 1,
                updated_at timestamp default current_timestamp
            )
            """.trimIndent()
        )
    }

    @BeforeTest
    fun resetData() {
        jdbcTemplate.update("delete from sys_user_session")
        jdbcTemplate.update("delete from sys_auth")
        jdbcTemplate.update("delete from sys_user")
    }

    @Test
    fun `change password updates hash and bumps password version`() {
        seedUser("alice", "P@ssw0rd1")
        val service = JdbcPasswordManagementService(jdbcTemplate, passwordEncoder, 8)

        val userId = service.changePassword(ChangePasswordCommand(1L, "P@ssw0rd1", "NewPass9"))

        val hash = jdbcTemplate.queryForObject(
            "select credential_hash from sys_auth where user_id = 1",
            String::class.java
        )!!
        val version = jdbcTemplate.queryForObject(
            "select password_version from sys_user where id = 1",
            Int::class.java
        )!!
        assertEquals(1L, userId)
        assertTrue(passwordEncoder.matches("NewPass9", hash))
        assertEquals(2, version)
    }

    @Test
    fun `reset password validates strength`() {
        seedUser("bob", "P@ssw0rd1")
        val service = JdbcPasswordManagementService(jdbcTemplate, passwordEncoder, 8)

        val error = assertFailsWith<PasswordValidationException> {
            service.resetPassword(ResetPasswordCommand("bob", "weak"))
        }

        assertEquals("auth.password.validation", error.message)
    }

    @Test
    fun `record failure locks user after threshold and reset clears state`() {
        seedUser("charlie", "P@ssw0rd1")
        val service = JdbcLoginAttemptService(jdbcTemplate, maxAttempts = 2, lockDurationMinutes = 30)

        val first = service.recordFailure("charlie")
        val second = service.recordFailure("charlie")

        assertEquals(1, first.remainingAttempts)
        assertTrue(second.locked)

        service.resetAttempts(1L)

        val row = jdbcTemplate.queryForMap(
            "select failed_login_attempts, locked_until from sys_user where id = 1"
        )
        assertEquals(0, (row["failed_login_attempts"] as Number).toInt())
        assertEquals(null, row["locked_until"])
    }

    @Test
    fun `revoke all sessions marks every active session as revoked`() {
        seedUser("delta", "P@ssw0rd1")
        jdbcTemplate.update(
            """
            insert into sys_user_session (
                session_id, user_id, username, status, created_at, updated_at
            ) values
                ('s1', 1, 'delta', 'ACTIVE', current_timestamp, current_timestamp),
                ('s2', 1, 'delta', 'ACTIVE', current_timestamp, current_timestamp)
            """.trimIndent()
        )
        val service = JdbcSessionManagementService(jdbcTemplate)

        val revokedCount = service.revokeAllSessions(1L, "PASSWORD_CHANGED")

        assertEquals(2, revokedCount)
        val rows = jdbcTemplate.queryForList(
            "select status, revoke_reason from sys_user_session where user_id = 1 order by session_id"
        )
        assertEquals(listOf("REVOKED", "REVOKED"), rows.map { it["status"] })
        assertEquals(listOf("PASSWORD_CHANGED", "PASSWORD_CHANGED"), rows.map { it["revoke_reason"] })
    }

    @Test
    fun `find latest session by device returns newest device session`() {
        seedUser("echo", "P@ssw0rd1")
        jdbcTemplate.update(
            """
            insert into sys_user_session (
                session_id, user_id, username, client_id, device_id, device_type, status, updated_at, created_at
            ) values
                ('s-old', 1, 'echo', 'web', 'device-1', 'WEB', 'ACTIVE', timestamp '2026-04-17 09:00:00', timestamp '2026-04-17 09:00:00'),
                ('s-new', 1, 'echo', 'web', 'device-1', 'WEB', 'REVOKED', timestamp '2026-04-17 10:00:00', timestamp '2026-04-17 10:00:00'),
                ('s-other', 1, 'echo', 'web', 'device-2', 'WEB', 'ACTIVE', timestamp '2026-04-17 11:00:00', timestamp '2026-04-17 11:00:00')
            """.trimIndent()
        )
        val service = JdbcSessionManagementService(jdbcTemplate)

        val session = service.findLatestSessionByDevice(1L, "device-1")

        assertEquals("s-new", session?.sessionId)
        assertEquals("REVOKED", session?.status)
        assertEquals("device-1", session?.deviceId)
    }

    @Test
    fun `revoke sessions by device only revokes active sessions on target device`() {
        seedUser("foxtrot", "P@ssw0rd1")
        jdbcTemplate.update(
            """
            insert into sys_user_session (
                session_id, user_id, username, client_id, device_id, device_type, status, created_at, updated_at
            ) values
                ('s1', 1, 'foxtrot', 'web', 'device-1', 'WEB', 'ACTIVE', current_timestamp, current_timestamp),
                ('s2', 1, 'foxtrot', 'web', 'device-1', 'WEB', 'ACTIVE', current_timestamp, current_timestamp),
                ('s3', 1, 'foxtrot', 'web', 'device-1', 'WEB', 'REVOKED', current_timestamp, current_timestamp),
                ('s4', 1, 'foxtrot', 'web', 'device-2', 'WEB', 'ACTIVE', current_timestamp, current_timestamp)
            """.trimIndent()
        )
        val service = JdbcSessionManagementService(jdbcTemplate)

        val revokedCount = service.revokeSessionsByDevice(1L, "device-1", "DEVICE_DEACTIVATED")

        assertEquals(2, revokedCount)
        val rows = jdbcTemplate.queryForList(
            "select session_id, status, revoke_reason from sys_user_session where user_id = 1 order by session_id"
        )
        assertEquals(listOf("REVOKED", "REVOKED", "REVOKED", "ACTIVE"), rows.map { it["status"] })
        assertEquals(listOf("DEVICE_DEACTIVATED", "DEVICE_DEACTIVATED", null, null), rows.map { it["revoke_reason"] })
    }

    private fun seedUser(username: String, rawPassword: String) {
        val userId = (jdbcTemplate.queryForObject("select coalesce(max(id), 0) + 1 from sys_user", Long::class.java) ?: 1L)
        jdbcTemplate.update(
            """
            insert into sys_user (id, username, display_name, status, password_version, failed_login_attempts, deleted)
            values (?, ?, ?, 1, 1, 0, 0)
            """.trimIndent(),
            userId,
            username,
            username
        )
        jdbcTemplate.update(
            """
            insert into sys_auth (user_id, identity_type, principal_key, credential_hash, enabled)
            values (?, 'PASSWORD', ?, ?, 1)
            """.trimIndent(),
            userId,
            username,
            passwordEncoder.encode(rawPassword)
        )
    }
}
