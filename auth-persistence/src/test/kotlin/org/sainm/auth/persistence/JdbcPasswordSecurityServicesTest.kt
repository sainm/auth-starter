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
        jdbcTemplate.update("delete from sys_auth")
        jdbcTemplate.update("delete from sys_user")
    }

    @Test
    fun `change password updates hash and bumps password version`() {
        seedUser("alice", "P@ssw0rd1")
        val service = JdbcPasswordManagementService(jdbcTemplate, passwordEncoder, 8)

        service.changePassword(ChangePasswordCommand(1L, "P@ssw0rd1", "NewPass9"))

        val hash = jdbcTemplate.queryForObject(
            "select credential_hash from sys_auth where user_id = 1",
            String::class.java
        )!!
        val version = jdbcTemplate.queryForObject(
            "select password_version from sys_user where id = 1",
            Int::class.java
        )!!
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
