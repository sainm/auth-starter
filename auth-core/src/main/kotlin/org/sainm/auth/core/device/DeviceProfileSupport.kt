package org.sainm.auth.core.device

import org.sainm.auth.core.spi.UserDeviceSummary
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit

enum class UserDeviceRiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

enum class UserDeviceAutoDisposition {
    NONE,
    REVIEW_ONLY,
    REVOKE_DEVICE_SESSIONS,
    DEACTIVATE_DEVICE_AND_REVOKE_SESSIONS
}

data class DeviceSignalPolicy(
    val enabled: Boolean = true,
    val riskLevel: UserDeviceRiskLevel = UserDeviceRiskLevel.MEDIUM,
    val autoDisposition: UserDeviceAutoDisposition = UserDeviceAutoDisposition.REVIEW_ONLY
)

data class DeviceGovernanceSignalPolicies(
    val deviceInactive: DeviceSignalPolicy = DeviceSignalPolicy(),
    val pushTokenMissing: DeviceSignalPolicy = DeviceSignalPolicy(),
    val authSessionMissing: DeviceSignalPolicy = DeviceSignalPolicy(),
    val abnormalAuthSessionStatus: DeviceSignalPolicy = DeviceSignalPolicy(),
    val authSessionStale: DeviceSignalPolicy = DeviceSignalPolicy(
        riskLevel = UserDeviceRiskLevel.HIGH,
        autoDisposition = UserDeviceAutoDisposition.REVOKE_DEVICE_SESSIONS
    ),
    val deviceStale: DeviceSignalPolicy = DeviceSignalPolicy(
        riskLevel = UserDeviceRiskLevel.HIGH,
        autoDisposition = UserDeviceAutoDisposition.REVIEW_ONLY
    ),
    val inactiveDeviceWithActiveSession: DeviceSignalPolicy = DeviceSignalPolicy(
        riskLevel = UserDeviceRiskLevel.CRITICAL,
        autoDisposition = UserDeviceAutoDisposition.REVOKE_DEVICE_SESSIONS
    ),
    val activeDeviceWithoutActiveSession: DeviceSignalPolicy = DeviceSignalPolicy(
        riskLevel = UserDeviceRiskLevel.HIGH,
        autoDisposition = UserDeviceAutoDisposition.REVIEW_ONLY
    )
)

data class DeviceGovernanceRiskPolicy(
    val deviceStaleDays: Long = 30,
    val sessionStaleDays: Long = 30,
    val requiredPushTokenDeviceTypes: Set<String> = setOf("ANDROID", "IOS"),
    val signalPolicies: DeviceGovernanceSignalPolicies = DeviceGovernanceSignalPolicies()
)

class DeviceProfileSupport(
    private val clock: Clock = Clock.systemUTC()
) {

    fun compose(
        summary: UserDeviceSummary,
        policy: DeviceGovernanceRiskPolicy = DeviceGovernanceRiskPolicy()
    ): UserDeviceSummary {
        val now = Instant.now(clock)
        val normalizedDeviceType = summary.deviceType.trim().uppercase()
        val triggeredSignals = buildList {
            if (!summary.activeFlag) {
                addTriggered("DEVICE_INACTIVE", policy.signalPolicies.deviceInactive)
            }
            if (
                normalizedDeviceType in policy.requiredPushTokenDeviceTypes &&
                summary.pushTokenMasked.isNullOrBlank()
            ) {
                addTriggered("PUSH_TOKEN_MISSING", policy.signalPolicies.pushTokenMissing)
            }
            if (summary.authSessionId == null) {
                addTriggered("AUTH_SESSION_MISSING", policy.signalPolicies.authSessionMissing)
            }
            when (summary.authSessionStatus) {
                null -> Unit
                "ACTIVE" -> Unit
                else -> addTriggered(
                    "AUTH_SESSION_${summary.authSessionStatus}",
                    policy.signalPolicies.abnormalAuthSessionStatus
                )
            }
            val authLastSeenAt = summary.authSessionLastSeenAt?.let(::parseInstant)
            if (authLastSeenAt != null && authLastSeenAt.isBefore(now.minus(policy.sessionStaleDays, ChronoUnit.DAYS))) {
                addTriggered("AUTH_SESSION_STALE", policy.signalPolicies.authSessionStale)
            }
            val deviceLastActiveAt = summary.lastActiveAt?.let(::parseInstant)
            if (deviceLastActiveAt != null && deviceLastActiveAt.isBefore(now.minus(policy.deviceStaleDays, ChronoUnit.DAYS))) {
                addTriggered("DEVICE_STALE", policy.signalPolicies.deviceStale)
            }
            if (!summary.activeFlag && summary.authSessionStatus == "ACTIVE") {
                addTriggered(
                    "INACTIVE_DEVICE_WITH_ACTIVE_SESSION",
                    policy.signalPolicies.inactiveDeviceWithActiveSession
                )
            }
            if (summary.activeFlag && summary.authSessionStatus != "ACTIVE") {
                addTriggered(
                    "ACTIVE_DEVICE_WITHOUT_ACTIVE_SESSION",
                    policy.signalPolicies.activeDeviceWithoutActiveSession
                )
            }
        }
        val signals = triggeredSignals.map(TriggeredSignal::code)

        val riskLevel = triggeredSignals
            .maxOfOrNull(TriggeredSignal::riskLevel)
            ?: UserDeviceRiskLevel.LOW

        val autoDisposition = triggeredSignals
            .maxOfOrNull(TriggeredSignal::autoDisposition)
            ?: UserDeviceAutoDisposition.NONE

        val trustLevel = when (riskLevel) {
            UserDeviceRiskLevel.LOW -> "TRUSTED"
            UserDeviceRiskLevel.MEDIUM -> "REVIEW"
            UserDeviceRiskLevel.HIGH,
            UserDeviceRiskLevel.CRITICAL -> "STALE"
        }

        val dispositionReason = triggeredSignals
            .firstOrNull { it.autoDisposition == autoDisposition && autoDisposition != UserDeviceAutoDisposition.NONE }
            ?.code
            ?: triggeredSignals.firstOrNull { it.riskLevel == riskLevel && riskLevel != UserDeviceRiskLevel.LOW }?.code

        return summary.copy(
            deviceTrustLevel = trustLevel,
            riskSignals = signals,
            riskLevel = riskLevel.name,
            autoDisposition = autoDisposition.name,
            autoDispositionReason = dispositionReason
        )
    }

    private fun parseInstant(value: String): Instant =
        Instant.parse(value)

    private fun MutableList<TriggeredSignal>.addTriggered(code: String, policy: DeviceSignalPolicy) {
        if (!policy.enabled) {
            return
        }
        add(
            TriggeredSignal(
                code = code,
                riskLevel = policy.riskLevel,
                autoDisposition = policy.autoDisposition
            )
        )
    }

    private data class TriggeredSignal(
        val code: String,
        val riskLevel: UserDeviceRiskLevel,
        val autoDisposition: UserDeviceAutoDisposition
    )
}
