package org.sainm.auth.persistence

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

class JdbcAuditQueryServiceTest {

    private val dataSource = DriverManagerDataSource().apply {
        setDriverClassName("org.h2.Driver")
        url = "jdbc:h2:mem:auth_audit_query_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1"
        username = "sa"
        password = ""
    }
    private val jdbcTemplate = JdbcTemplate(dataSource)
    private val objectMapper = ObjectMapper()

    init {
        jdbcTemplate.execute("drop table if exists sys_security_event")
        jdbcTemplate.execute("drop table if exists sys_login_log")
        jdbcTemplate.execute(
            """
            create table sys_login_log (
                id bigserial primary key,
                user_id bigint,
                principal varchar(191),
                login_type varchar(32) not null,
                result varchar(32) not null,
                ip varchar(64),
                user_agent varchar(512),
                location varchar(255),
                reason varchar(255),
                created_at timestamp default current_timestamp
            )
            """.trimIndent()
        )
        jdbcTemplate.execute(
            """
            create table sys_security_event (
                id bigserial primary key,
                event_type varchar(64) not null,
                user_id bigint,
                tenant_id bigint,
                detail_json varchar(1024),
                ip varchar(64),
                created_at timestamp default current_timestamp
            )
            """.trimIndent()
        )
    }

    @BeforeTest
    fun resetData() {
        jdbcTemplate.update("delete from sys_security_event")
        jdbcTemplate.update("delete from sys_login_log")
    }

    @Test
    fun `find login logs applies filters and orders latest first`() {
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, reason, created_at) values (1, 11, 'alice', 'PASSWORD', 'SUCCESS', null, CURRENT_TIMESTAMP - 2)"
        )
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, reason, created_at) values (2, 12, 'alice', 'PASSWORD', 'FAIL', 'bad password', CURRENT_TIMESTAMP - 1)"
        )
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, reason, created_at) values (3, 13, 'bob', 'PASSWORD', 'FAIL', 'locked', CURRENT_TIMESTAMP)"
        )

        val service = JdbcAuditQueryService(jdbcTemplate, objectMapper)

        val filtered = service.findLoginLogs(page = 1, size = 10, principal = "alice", result = "FAIL")

        assertEquals(listOf(2L), filtered.map { it.id })
        assertEquals("bad password", filtered.single().reason)
    }

    @Test
    fun `find login logs paginates with normalized offset`() {
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, created_at) values (1, 11, 'alice', 'PASSWORD', 'SUCCESS', CURRENT_TIMESTAMP - 2)"
        )
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, created_at) values (2, 12, 'bob', 'PASSWORD', 'SUCCESS', CURRENT_TIMESTAMP - 1)"
        )
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, created_at) values (3, 13, 'carol', 'PASSWORD', 'SUCCESS', CURRENT_TIMESTAMP)"
        )

        val service = JdbcAuditQueryService(jdbcTemplate, objectMapper)

        val firstPage = service.findLoginLogs(page = 1, size = 2, principal = null, result = null)
        val normalizedPage = service.findLoginLogs(page = 0, size = 2, principal = null, result = null)

        assertEquals(listOf(3L, 2L), firstPage.map { it.id })
        assertEquals(firstPage.map { it.id }, normalizedPage.map { it.id })
    }

    @Test
    fun `find security events filters and orders latest first`() {
        jdbcTemplate.update(
            "insert into sys_security_event (id, event_type, user_id, tenant_id, detail_json, ip, created_at) values (1, 'LOGIN', 11, 1, '{\"step\":\"start\"}', '127.0.0.1', CURRENT_TIMESTAMP - 2)"
        )
        jdbcTemplate.update(
            "insert into sys_security_event (id, event_type, user_id, tenant_id, detail_json, ip, created_at) values (2, 'ACCESS_DENIED', 12, 1, '{\"path\":\"/auth/users\"}', '127.0.0.2', CURRENT_TIMESTAMP - 1)"
        )
        jdbcTemplate.update(
            "insert into sys_security_event (id, event_type, user_id, tenant_id, detail_json, ip, created_at) values (3, 'ACCESS_DENIED', 13, 2, '{\"path\":\"/auth/admin\"}', '127.0.0.3', CURRENT_TIMESTAMP)"
        )

        val service = JdbcAuditQueryService(jdbcTemplate, objectMapper)

        val filtered = service.findSecurityEvents(page = 1, size = 10, eventType = "ACCESS_DENIED")

        assertEquals(listOf(3L, 2L), filtered.map { it.id })
        assertEquals("127.0.0.3", filtered.first().ip)
    }

    @Test
    fun `find my login activities returns latest records for principal or user`() {
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, ip, user_agent, location, reason, created_at) values (1, 11, 'alice', 'PASSWORD', 'SUCCESS', '127.0.0.1', 'ua-1', 'Hangzhou', null, CURRENT_TIMESTAMP - 2)"
        )
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, ip, user_agent, location, reason, created_at) values (2, 12, 'alice', 'PASSWORD', 'FAIL', '127.0.0.2', 'ua-2', 'Shanghai', 'bad password', CURRENT_TIMESTAMP - 1)"
        )
        jdbcTemplate.update(
            "insert into sys_login_log (id, user_id, principal, login_type, result, ip, user_agent, location, reason, created_at) values (3, 13, 'bob', 'PASSWORD', 'SUCCESS', '127.0.0.3', 'ua-3', 'Beijing', null, CURRENT_TIMESTAMP)"
        )

        val service = JdbcAuditQueryService(jdbcTemplate, objectMapper)

        val records = service.findMyLoginActivities(userId = 11, principal = "alice", limit = 10)

        assertEquals(listOf(2L, 1L), records.map { it.id })
        assertEquals("ua-2", records.first().userAgent)
    }

    @Test
    fun `find my security events parses detail json`() {
        jdbcTemplate.update(
            "insert into sys_security_event (id, event_type, user_id, tenant_id, detail_json, ip, created_at) values (1, 'ACCESS_DENIED', 11, 1, '{\"path\":\"/auth/me\"}', '127.0.0.1', CURRENT_TIMESTAMP - 1)"
        )
        jdbcTemplate.update(
            "insert into sys_security_event (id, event_type, user_id, tenant_id, detail_json, ip, created_at) values (2, 'LOGIN', 12, 1, '{\"step\":\"done\"}', '127.0.0.2', CURRENT_TIMESTAMP)"
        )

        val service = JdbcAuditQueryService(jdbcTemplate, objectMapper)

        val records = service.findMySecurityEvents(userId = 11, limit = 10)

        assertEquals(listOf(1L), records.map { it.id })
        assertEquals("/auth/me", records.single().detail["path"])
    }
}
