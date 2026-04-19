package org.sainm.auth.core.device

import org.sainm.auth.core.spi.UserDeviceSummary
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId

enum class DeviceTrustLevel {
    TRUSTED,
    REVIEW,
    STALE
}

enum class DeviceAutoAction {
    NONE,
    REVIEW,
    REVOKE_SESSIONS,
    DEACTIVATE_DEVICE
}

enum class DeviceRiskSignal(val code: String) {
    DEVICE_INACTIVE("DEVICE_INACTIVE"),
    PUSH_TOKEN_MISSING("PUSH_TOKEN_MISSING"),
    AUTH_SESSION_MISSING("AUTH_SESSION_MISSING"),
    AUTH_SESSION_STALE("AUTH_SESSION_STALE"),
    DEVICE_STALE("DEVICE_STALE"),
    ACTIVE_DEVICE_WITHOUT_ACTIVE_SESSION("ACTIVE_DEVICE_WITHOUT_ACTIVE_SESSION")
}

data class DeviceGovernanceAssessment(
    val trustLevel: DeviceTrustLevel,
    val riskSignals: List<String>,
    val recommendedAction: DeviceAutoAction
)

interface DeviceGovernanceEvaluator {
    fun assess(summary: UserDeviceSummary, now: LocalDateTime = LocalDateTime.now()): DeviceGovernanceAssessment
}

class DefaultDeviceGovernanceEvaluator(
    private val staleThresholdDays: Long = 30
) : DeviceGovernanceEvaluator {

    override fun assess(summary: UserDeviceSummary, now: LocalDateTime): DeviceGovernanceAssessment {
        val signals = buildList {
            if (!summary.activeFlag) {
                add(DeviceRiskSignal.DEVICE_INACTIVE.code)
            }
            if (summary.pushTokenMasked.isNullOrBlank()) {
                add(DeviceRiskSignal.PUSH_TOKEN_MISSING.code)
            }
            if (summary.authSessionId.isNullOrBlank()) {
                add(DeviceRiskSignal.AUTH_SESSION_MISSING.code)
            }

            summary.authSessionStatus
                ?.trim()
                ?.takeIf { it.isNotEmpty() && !it.equals("ACTIVE", ignoreCase = true) }
                ?.let { add("AUTH_SESSION_${it.uppercase()}") }

            summary.authSessionLastSeenAt
                ?.parseDeviceTime()
                ?.takeIf { it.isBefore(now.minusDays(staleThresholdDays)) }
                ?.let { add(DeviceRiskSignal.AUTH_SESSION_STALE.code) }

            summary.lastActiveAt
                ?.parseDeviceTime()
                ?.takeIf { it.isBefore(now.minusDays(staleThresholdDays)) }
                ?.let { add(DeviceRiskSignal.DEVICE_STALE.code) }

            if (summary.activeFlag && summary.authSessionStatus?.equals("ACTIVE", ignoreCase = true) != true) {
                add(DeviceRiskSignal.ACTIVE_DEVICE_WITHOUT_ACTIVE_SESSION.code)
            }
        }

        val trustLevel = when {
            !summary.activeFlag || signals.any { it == "AUTH_SESSION_STALE" || it == "DEVICE_STALE" } -> DeviceTrustLevel.STALE
            signals.isEmpty() -> DeviceTrustLevel.TRUSTED
            else -> DeviceTrustLevel.REVIEW
        }

        val recommendedAction = when {
            !summary.activeFlag -> DeviceAutoAction.DEACTIVATE_DEVICE
            DeviceRiskSignal.ACTIVE_DEVICE_WITHOUT_ACTIVE_SESSION.code in signals -> DeviceAutoAction.REVOKE_SESSIONS
            signals.isNotEmpty() -> DeviceAutoAction.REVIEW
            else -> DeviceAutoAction.NONE
        }

        return DeviceGovernanceAssessment(
            trustLevel = trustLevel,
            riskSignals = signals,
            recommendedAction = recommendedAction
        )
    }
}

fun UserDeviceSummary.assessGovernance(
    now: LocalDateTime = LocalDateTime.now(),
    staleThresholdDays: Long = 30
): DeviceGovernanceAssessment =
    DefaultDeviceGovernanceEvaluator(staleThresholdDays).assess(this, now)

fun UserDeviceSummary.withGovernanceAssessment(
    now: LocalDateTime = LocalDateTime.now(),
    staleThresholdDays: Long = 30
): UserDeviceSummary {
    val assessment = assessGovernance(now, staleThresholdDays)
    return copy(
        deviceTrustLevel = assessment.trustLevel.name,
        riskSignals = assessment.riskSignals
    )
}

private fun String.parseDeviceTime(): LocalDateTime =
    runCatching { LocalDateTime.parse(this) }
        .recoverCatching {
            Instant.parse(this).atZone(ZoneId.systemDefault()).toLocalDateTime()
        }
        .getOrElse { throw IllegalArgumentException("Invalid device timestamp: $this", it) }
