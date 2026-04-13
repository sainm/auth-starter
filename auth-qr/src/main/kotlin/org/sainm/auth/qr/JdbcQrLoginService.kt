package org.sainm.auth.qr

import org.sainm.auth.core.spi.QrLoginResult
import org.sainm.auth.core.spi.QrLoginService
import org.sainm.auth.core.spi.QrSceneSummary
import org.sainm.auth.core.spi.UserLookupService
import org.springframework.jdbc.core.JdbcTemplate
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

class JdbcQrLoginService(
    private val jdbcTemplate: JdbcTemplate,
    private val userLookupService: UserLookupService,
    private val ttlSeconds: Long = 180
) : QrLoginService {

    override fun createScene(): QrSceneSummary {
        val sceneCode = UUID.randomUUID().toString().replace("-", "")
        val expiresAt = Instant.now().plusSeconds(ttlSeconds)
        jdbcTemplate.update(
            """
            insert into sys_qr_scene (scene_code, status, expire_at)
            values (?, 'PENDING', ?)
            """.trimIndent(),
            sceneCode,
            Timestamp.from(expiresAt)
        )
        return QrSceneSummary(sceneCode = sceneCode, status = "PENDING", expiresAtEpochSecond = expiresAt.epochSecond)
    }

    override fun getScene(sceneCode: String): QrSceneSummary? {
        expireIfNeeded(sceneCode)
        return jdbcTemplate.query(
            """
            select scene_code, status, expire_at, scanned_user_id, approved_user_id
            from sys_qr_scene
            where scene_code = ?
            """.trimIndent(),
            { rs, _ ->
                QrSceneSummary(
                    sceneCode = rs.getString("scene_code"),
                    status = rs.getString("status"),
                    expiresAtEpochSecond = rs.getTimestamp("expire_at").toInstant().epochSecond,
                    scannedUserId = rs.getObject("scanned_user_id")?.let { (it as Number).toLong() },
                    approvedUserId = rs.getObject("approved_user_id")?.let { (it as Number).toLong() }
                )
            },
            sceneCode
        ).firstOrNull()
    }

    override fun scanScene(sceneCode: String, userId: Long): QrSceneSummary {
        val scene = requireActiveScene(sceneCode)
        if (scene.status != "PENDING" && scene.status != "SCANNED") {
            throw IllegalArgumentException("auth.qr.scene.scan.invalidStatus")
        }
        val updated = jdbcTemplate.update(
            """
            update sys_qr_scene
            set status = 'SCANNED',
                scanned_user_id = ?,
                scanned_at = current_timestamp
            where scene_code = ?
              and status in ('PENDING', 'SCANNED')
            """.trimIndent(),
            userId,
            sceneCode
        )
        if (updated != 1) {
            throw IllegalStateException("QR scene state changed while scanning")
        }
        return scene.copy(status = "SCANNED", scannedUserId = userId)
    }

    override fun confirmScene(sceneCode: String, userId: Long): QrSceneSummary {
        val scene = requireActiveScene(sceneCode)
        if (scene.status != "SCANNED") {
            throw IllegalArgumentException("auth.qr.scene.confirm.invalidStatus")
        }
        val scannedUserId = scene.scannedUserId
        if (scannedUserId != null && scannedUserId != userId) {
            throw IllegalArgumentException("auth.qr.scene.scannedByAnotherUser")
        }
        val updated = jdbcTemplate.update(
            """
            update sys_qr_scene
            set status = 'APPROVED',
                approved_user_id = ?,
                approved_at = current_timestamp
            where scene_code = ?
              and status = 'SCANNED'
            """.trimIndent(),
            userId,
            sceneCode
        )
        if (updated != 1) {
            throw IllegalStateException("QR scene state changed while confirming")
        }
        return scene.copy(status = "APPROVED", approvedUserId = userId)
    }

    override fun cancelScene(sceneCode: String, userId: Long?): QrSceneSummary {
        val scene = requireActiveScene(sceneCode)
        if (scene.status in setOf("CANCELED", "CONSUMED", "EXPIRED")) {
            return scene
        }
        if (userId != null && scene.scannedUserId != null && scene.scannedUserId != userId && scene.approvedUserId != userId) {
            throw IllegalArgumentException("auth.qr.scene.belongsToAnotherUser")
        }
        val updated = jdbcTemplate.update(
            """
            update sys_qr_scene
            set status = 'CANCELED'
            where scene_code = ?
              and status in ('PENDING', 'SCANNED')
            """.trimIndent(),
            sceneCode
        )
        if (updated != 1) {
            return getScene(sceneCode) ?: error("QR scene missing after cancel")
        }
        return scene.copy(status = "CANCELED")
    }

    override fun consumeScene(sceneCode: String): QrLoginResult? {
        val scene = getScene(sceneCode) ?: return null
        if (scene.status != "APPROVED") {
            return null
        }
        val updated = jdbcTemplate.update(
            """
            update sys_qr_scene
            set status = 'CONSUMED',
                consumed_at = current_timestamp
            where scene_code = ?
              and status = 'APPROVED'
            """.trimIndent(),
            sceneCode
        )
        if (updated != 1) {
            return null
        }
        val approvedUserId = scene.approvedUserId ?: return null
        val user = userLookupService.findById(approvedUserId) ?: return null
        return QrLoginResult(scene = scene.copy(status = "CONSUMED"), user = user)
    }

    override fun cleanupExpiredScenes(retentionSeconds: Long): Int =
        jdbcTemplate.update(
            """
            delete from sys_qr_scene
            where status in ('EXPIRED', 'CANCELED', 'CONSUMED')
              and expire_at < ?
            """.trimIndent(),
            Timestamp.from(Instant.now().minusSeconds(retentionSeconds))
        )

    private fun requireActiveScene(sceneCode: String): QrSceneSummary {
        val scene = getScene(sceneCode) ?: throw IllegalArgumentException("auth.qr.scene.notFound")
        if (scene.status == "EXPIRED") {
            throw IllegalArgumentException("auth.qr.scene.expired")
        }
        return scene
    }

    private fun expireIfNeeded(sceneCode: String) {
        jdbcTemplate.update(
            """
            update sys_qr_scene
            set status = 'EXPIRED'
            where scene_code = ?
              and status not in ('EXPIRED', 'CONSUMED', 'CANCELED')
              and expire_at <= current_timestamp
            """.trimIndent(),
            sceneCode
        )
    }
}
