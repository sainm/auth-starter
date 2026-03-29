package org.sainm.auth.qr

import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.spi.UserCredentialView
import org.sainm.auth.core.spi.UserLookupService
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import java.sql.Timestamp
import java.time.Instant
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JdbcQrLoginServiceTest {

    private val dataSource = DriverManagerDataSource().apply {
        setDriverClassName("org.h2.Driver")
        url = "jdbc:h2:mem:auth_qr_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1"
        username = "sa"
        password = ""
    }
    private val jdbcTemplate = JdbcTemplate(dataSource)
    private val userLookupService = object : UserLookupService {
        override fun findById(userId: Long): UserPrincipal =
            UserPrincipal(userId, "user$userId", "User $userId", UserStatus.ENABLED, null, null)

        override fun findByPrincipal(principal: String): UserCredentialView? = null
    }

    init {
        jdbcTemplate.execute("drop table if exists sys_qr_scene")
        jdbcTemplate.execute(
            """
            create table sys_qr_scene (
                id bigserial primary key,
                scene_code varchar(64) not null,
                status varchar(32) not null,
                scanned_user_id bigint,
                scanned_at timestamp,
                approved_user_id bigint,
                approved_at timestamp,
                consumed_at timestamp,
                expire_at timestamp not null,
                created_at timestamp default current_timestamp
            )
            """.trimIndent()
        )
    }

    @BeforeTest
    fun resetData() {
        jdbcTemplate.update("delete from sys_qr_scene")
    }

    @Test
    fun `scene flows from scanned to approved to consumed`() {
        val service = JdbcQrLoginService(jdbcTemplate, userLookupService)

        val scene = service.createScene()
        val scanned = service.scanScene(scene.sceneCode, 1L)
        val approved = service.confirmScene(scene.sceneCode, 1L)
        val consumed = service.consumeScene(scene.sceneCode)

        assertEquals("SCANNED", scanned.status)
        assertEquals(1L, scanned.scannedUserId)
        assertEquals("APPROVED", approved.status)
        assertEquals(1L, approved.approvedUserId)
        assertNotNull(consumed)
        assertEquals("CONSUMED", consumed.scene.status)
    }

    @Test
    fun `cancelled scene cannot be consumed`() {
        val service = JdbcQrLoginService(jdbcTemplate, userLookupService)

        val scene = service.createScene()
        val canceled = service.cancelScene(scene.sceneCode, null)

        assertEquals("CANCELED", canceled.status)
        assertNull(service.consumeScene(scene.sceneCode))
    }

    @Test
    fun `cleanup removes expired terminal scenes`() {
        val service = JdbcQrLoginService(jdbcTemplate, userLookupService, ttlSeconds = 1)
        val scene = service.createScene()
        jdbcTemplate.update(
            """
            update sys_qr_scene
            set status = 'EXPIRED',
                expire_at = ?
            where scene_code = ?
            """.trimIndent(),
            Timestamp.from(Instant.now().minusSeconds(172800)),
            scene.sceneCode
        )

        val deleted = service.cleanupExpiredScenes(retentionSeconds = 60)

        assertEquals(1, deleted)
        assertTrue(jdbcTemplate.queryForObject("select count(*) from sys_qr_scene", Int::class.java) == 0)
    }
}
