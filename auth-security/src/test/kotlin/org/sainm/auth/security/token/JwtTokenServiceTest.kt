package org.sainm.auth.security.token

import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.exception.InvalidTokenException
import org.sainm.auth.core.spi.SessionManagementService
import org.sainm.auth.core.spi.SessionOpenCommand
import org.sainm.auth.core.spi.SessionPolicyMode
import org.sainm.auth.core.spi.SessionTokenContext
import org.sainm.auth.core.spi.UserSessionSummary
import org.sainm.auth.core.spi.TokenBlacklistService
import org.sainm.auth.core.spi.UserCredentialView
import org.sainm.auth.core.spi.UserLookupService
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JwtTokenServiceTest {

    private val principal = UserPrincipal(
        userId = 7L,
        username = "tester",
        displayName = "Tester",
        status = UserStatus.ENABLED,
        groupId = 2L,
        tenantId = 3L,
        roles = setOf("ADMIN"),
        permissions = setOf("api:GET:/auth/me"),
        attributes = mapOf("passwordVersion" to 1)
    )

    @Test
    fun `generate and parse preserves principal claims`() {
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            )
        )

        val tokenPair = service.generate(principal)
        val parsed = service.parse(tokenPair.accessToken)

        assertEquals(principal.userId, parsed.userId)
        assertEquals(principal.username, parsed.username)
        assertEquals(principal.roles, parsed.roles)
        assertEquals(principal.permissions, parsed.permissions)
        assertEquals(principal.groupId, parsed.groupId)
        assertEquals(principal.tenantId, parsed.tenantId)
    }

    @Test
    fun `refresh invalidates old refresh token`() {
        val blacklist = InMemoryTokenBlacklistService()
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            tokenBlacklistService = blacklist
        )

        val tokenPair = service.generate(principal)
        val refreshed = service.refresh(tokenPair.refreshToken)

        assertTrue(refreshed.accessToken.isNotBlank())
        assertFailsWith<InvalidTokenException> {
            service.refresh(tokenPair.refreshToken)
        }
    }

    @Test
    fun `refresh token misuse returns readable message`() {
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            )
        )

        val tokenPair = service.generate(principal)
        val error = assertFailsWith<InvalidTokenException> {
            service.refresh(tokenPair.accessToken)
        }

        assertEquals("auth.refreshToken.invalid", error.message)
    }

    @Test
    fun `invalidate blacklists access token`() {
        val blacklist = InMemoryTokenBlacklistService()
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            tokenBlacklistService = blacklist
        )

        val tokenPair = service.generate(principal)
        service.invalidate(tokenPair.accessToken)

        assertFailsWith<InvalidTokenException> {
            service.parse(tokenPair.accessToken)
        }
    }

    @Test
    fun `password version mismatch invalidates old token`() {
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            userLookupService = object : UserLookupService {
                override fun findById(userId: Long): UserPrincipal =
                    principal.copy(attributes = mapOf("passwordVersion" to 2))

                override fun findByPrincipal(principal: String): UserCredentialView? = null
            }
        )

        val tokenPair = service.generate(principal)

        assertFailsWith<InvalidTokenException> {
            service.parse(tokenPair.accessToken)
        }
    }

    @Test
    fun `invalid signature returns readable message`() {
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            )
        )
        val otherService = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "another-secret-another-secret-1234",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            )
        )

        val tokenPair = service.generate(principal)
        val error = assertFailsWith<InvalidTokenException> {
            otherService.parse(tokenPair.accessToken)
        }

        assertEquals("auth.token.signature.invalid", error.message)
    }

    @Test
    fun `password version lookup is cached briefly across parses`() {
        val lookupService = CountingUserLookupService(principal)
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            userLookupService = lookupService,
            clock = Clock.fixed(Instant.parse("2026-04-13T00:00:00Z"), ZoneOffset.UTC),
            passwordVersionCacheTtlSeconds = 60
        )

        val tokenPair = service.generate(principal)

        service.parse(tokenPair.accessToken)
        service.parse(tokenPair.accessToken)

        assertEquals(1, lookupService.findByIdCalls)
    }

    @Test
    fun `refresh parses token only once for password version lookup`() {
        val lookupService = CountingUserLookupService(principal)
        val blacklist = InMemoryTokenBlacklistService()
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            tokenBlacklistService = blacklist,
            userLookupService = lookupService,
            clock = Clock.fixed(Instant.parse("2026-04-13T00:00:00Z"), ZoneOffset.UTC),
            passwordVersionCacheTtlSeconds = 60
        )

        val tokenPair = service.generate(principal)
        service.refresh(tokenPair.refreshToken)

        assertEquals(1, lookupService.findByIdCalls)
    }

    @Test
    fun `invalidate does not query password version`() {
        val lookupService = CountingUserLookupService(principal)
        val blacklist = InMemoryTokenBlacklistService()
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            tokenBlacklistService = blacklist,
            userLookupService = lookupService
        )

        val tokenPair = service.generate(principal)
        service.invalidate(tokenPair.accessToken)

        assertEquals(0, lookupService.findByIdCalls)
        assertFailsWith<InvalidTokenException> {
            service.parse(tokenPair.accessToken)
        }
    }

    @Test
    fun `generate and parse preserves stable device id`() {
        val sessionService = RecordingSessionManagementService()
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            sessionManagementService = sessionService
        )

        val tokenPair = service.generate(
            principal.copy(
                attributes = principal.attributes + mapOf(
                    "deviceId" to "web-device-001",
                    "clientId" to "admin-web"
                )
            )
        )
        val parsed = service.parse(tokenPair.accessToken)

        assertEquals("web-device-001", parsed.attributes["deviceId"])
        assertEquals("web-device-001", sessionService.lastOpenCommand?.deviceId)
    }
}

private class InMemoryTokenBlacklistService : TokenBlacklistService {
    private val blacklisted = mutableSetOf<String>()

    override fun blacklist(jti: String, userId: Long, expireAtEpochSecond: Long) {
        blacklisted += jti
    }

    override fun isBlacklisted(jti: String): Boolean = jti in blacklisted
}

private class CountingUserLookupService(
    private val user: UserPrincipal
) : UserLookupService {
    var findByIdCalls: Int = 0

    override fun findById(userId: Long): UserPrincipal {
        findByIdCalls++
        return user
    }

    override fun findByPrincipal(principal: String): UserCredentialView? = null
}

private class RecordingSessionManagementService : SessionManagementService {
    var lastOpenCommand: SessionOpenCommand? = null

    override fun openSession(command: SessionOpenCommand): SessionTokenContext {
        lastOpenCommand = command
        return SessionTokenContext("session-1", SessionPolicyMode.MULTI_DEVICE)
    }

    override fun touchSession(sessionId: String, userId: Long, accessExpireAtEpochSecond: Long, refreshExpireAtEpochSecond: Long): Boolean = true
    override fun recordSessionActivity(sessionId: String, userId: Long): Boolean = true
    override fun isSessionActive(sessionId: String, userId: Long): Boolean = true
    override fun listSessions(userId: Long, limit: Int): List<UserSessionSummary> = emptyList()
    override fun findLatestSessionByDevice(userId: Long, deviceId: String): UserSessionSummary? = null
    override fun revokeSession(userId: Long, sessionId: String, reason: String?): Boolean = true
    override fun revokeSessionsByDevice(userId: Long, deviceId: String, reason: String?): Int = 0
    override fun revokeOtherSessions(userId: Long, currentSessionId: String, reason: String?): Int = 0
    override fun revokeAllSessions(userId: Long, reason: String?): Int = 0
    override fun getPolicy(userId: Long): SessionPolicyMode = SessionPolicyMode.MULTI_DEVICE
    override fun updatePolicy(userId: Long, policy: SessionPolicyMode): SessionPolicyMode = policy
}
