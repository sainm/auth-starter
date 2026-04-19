package org.sainm.auth.core.device

import org.sainm.auth.core.spi.UserDeviceSummary
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DeviceGovernanceEvaluatorTest {

    private val support = DeviceProfileSupport(
        clock = Clock.fixed(Instant.parse("2026-04-18T00:00:00Z"), ZoneOffset.UTC)
    )

    @Test
    fun `trusted active device stays trusted`() {
        val summary = device(
            activeFlag = true,
            pushTokenMasked = "push****1234",
            authSessionId = "session-1",
            authSessionStatus = "ACTIVE",
            authSessionLastSeenAt = "2026-04-17T20:00:00Z",
            lastActiveAt = "2026-04-17T20:00:00Z"
        )

        val assessment = support.compose(summary)

        assertEquals("TRUSTED", assessment.deviceTrustLevel)
        assertTrue(assessment.riskSignals.isEmpty())
        assertEquals(UserDeviceAutoDisposition.NONE.name, assessment.autoDisposition)
    }

    @Test
    fun `inactive device is stale and suggests deactivation`() {
        val summary = device(
            activeFlag = false,
            pushTokenMasked = null,
            authSessionId = null,
            authSessionStatus = null,
            authSessionLastSeenAt = null,
            lastActiveAt = "2026-03-01T00:00:00Z"
        )

        val assessment = support.compose(summary)

        assertEquals("STALE", assessment.deviceTrustLevel)
        assertTrue("DEVICE_INACTIVE" in assessment.riskSignals)
        assertTrue("PUSH_TOKEN_MISSING" !in assessment.riskSignals)
        assertTrue("AUTH_SESSION_MISSING" in assessment.riskSignals)
        assertTrue("DEVICE_STALE" in assessment.riskSignals)
        assertEquals(UserDeviceAutoDisposition.REVIEW_ONLY.name, assessment.autoDisposition)
    }

    @Test
    fun `active device without active session suggests revoke sessions`() {
        val summary = device(
            activeFlag = true,
            pushTokenMasked = "push****1234",
            authSessionId = "session-2",
            authSessionStatus = "REVOKED",
            authSessionLastSeenAt = "2026-04-17T00:00:00Z",
            lastActiveAt = "2026-04-17T00:00:00Z"
        )

        val assessment = support.compose(
            summary,
            DeviceGovernanceRiskPolicy(
                signalPolicies = DeviceGovernanceSignalPolicies(
                    activeDeviceWithoutActiveSession = DeviceSignalPolicy(
                        riskLevel = UserDeviceRiskLevel.HIGH,
                        autoDisposition = UserDeviceAutoDisposition.DEACTIVATE_DEVICE_AND_REVOKE_SESSIONS
                    )
                )
            )
        )

        assertEquals("STALE", assessment.deviceTrustLevel)
        assertTrue("ACTIVE_DEVICE_WITHOUT_ACTIVE_SESSION" in assessment.riskSignals)
        assertTrue("AUTH_SESSION_REVOKED" in assessment.riskSignals)
        assertEquals(UserDeviceAutoDisposition.DEACTIVATE_DEVICE_AND_REVOKE_SESSIONS.name, assessment.autoDisposition)
    }

    @Test
    fun `web device can ignore missing push token by default`() {
        val summary = device(
            deviceType = "WEB",
            activeFlag = true,
            pushTokenMasked = null,
            authSessionId = "session-3",
            authSessionStatus = "ACTIVE",
            authSessionLastSeenAt = "2026-04-17T20:00:00Z",
            lastActiveAt = "2026-04-17T20:00:00Z"
        )

        val assessment = support.compose(summary)

        assertEquals("TRUSTED", assessment.deviceTrustLevel)
        assertTrue("PUSH_TOKEN_MISSING" !in assessment.riskSignals)
        assertEquals(UserDeviceAutoDisposition.NONE.name, assessment.autoDisposition)
    }

    @Test
    fun `push token missing policy can be tightened for web device`() {
        val summary = device(
            deviceType = "WEB",
            activeFlag = true,
            pushTokenMasked = null,
            authSessionId = "session-4",
            authSessionStatus = "ACTIVE",
            authSessionLastSeenAt = "2026-04-17T20:00:00Z",
            lastActiveAt = "2026-04-17T20:00:00Z"
        )

        val assessment = support.compose(
            summary,
            DeviceGovernanceRiskPolicy(
                requiredPushTokenDeviceTypes = setOf("WEB"),
                signalPolicies = DeviceGovernanceSignalPolicies(
                    pushTokenMissing = DeviceSignalPolicy(
                        riskLevel = UserDeviceRiskLevel.HIGH,
                        autoDisposition = UserDeviceAutoDisposition.REVIEW_ONLY
                    )
                )
            )
        )

        assertEquals("STALE", assessment.deviceTrustLevel)
        assertTrue("PUSH_TOKEN_MISSING" in assessment.riskSignals)
        assertEquals(UserDeviceAutoDisposition.REVIEW_ONLY.name, assessment.autoDisposition)
        assertEquals("PUSH_TOKEN_MISSING", assessment.autoDispositionReason)
    }

    @Test
    fun `assessment can be copied back into summary`() {
        val summary = device(
            activeFlag = true,
            pushTokenMasked = null,
            authSessionId = null,
            authSessionStatus = null,
            authSessionLastSeenAt = null,
            lastActiveAt = null
        )

        val enriched = support.compose(summary)

        assertEquals("STALE", enriched.deviceTrustLevel)
        assertTrue("PUSH_TOKEN_MISSING" !in enriched.riskSignals)
        assertTrue("AUTH_SESSION_MISSING" in enriched.riskSignals)
    }

    private fun device(
        deviceType: String = "WEB",
        activeFlag: Boolean,
        pushTokenMasked: String?,
        authSessionId: String?,
        authSessionStatus: String?,
        authSessionLastSeenAt: String?,
        lastActiveAt: String?
        ): UserDeviceSummary =
        UserDeviceSummary(
            id = 1L,
            deviceType = deviceType,
            deviceId = "device-1",
            pushTokenMasked = pushTokenMasked,
            appVersion = "1.0.0",
            activeFlag = activeFlag,
            authSessionId = authSessionId,
            authSessionStatus = authSessionStatus,
            authSessionLastSeenAt = authSessionLastSeenAt,
            deviceTrustLevel = "REVIEW",
            riskSignals = emptyList(),
            riskLevel = "LOW",
            autoDisposition = "NONE",
            autoDispositionReason = null,
            lastActiveAt = lastActiveAt,
            createdAt = "2026-04-17T00:00:00",
            updatedAt = "2026-04-17T00:00:00"
        )
}
