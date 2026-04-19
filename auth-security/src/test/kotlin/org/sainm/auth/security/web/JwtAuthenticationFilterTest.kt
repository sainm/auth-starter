package org.sainm.auth.security.web

import jakarta.servlet.http.HttpServletResponse
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.spi.SessionManagementService
import org.sainm.auth.core.spi.SessionOpenCommand
import org.sainm.auth.core.spi.SessionPolicyMode
import org.sainm.auth.core.spi.SessionTokenContext
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserSessionSummary
import org.sainm.auth.security.context.TenantContextHolder
import org.springframework.http.HttpHeaders
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.context.SecurityContextHolder
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JwtAuthenticationFilterTest {

    @AfterTest
    fun cleanup() {
        SecurityContextHolder.clearContext()
        TenantContextHolder.clear()
    }

    @Test
    fun `successful bearer request populates security context and records activity once per interval`() {
        val sessionService = RecordingSessionManagementService()
        val principal = userPrincipal()
        val filter = JwtAuthenticationFilter(
            tokenService = StaticTokenService(principal),
            sessionManagementService = sessionService,
            clock = Clock.fixed(Instant.parse("2026-04-17T00:00:00Z"), ZoneOffset.UTC),
            activityTouchIntervalSeconds = 60
        )

        val request = MockHttpServletRequest().apply {
            addHeader(HttpHeaders.AUTHORIZATION, "Bearer ok-token")
        }
        val response = MockHttpServletResponse()
        val chain = CapturingFilterChain()

        filter.doFilter(request, response, chain)

        val authentication = chain.authentication
        assertEquals(7L, authentication?.principal)
        val credentials = authentication?.credentials as UserPrincipal
        assertEquals("session-7", credentials.attributes["sessionId"])
        assertTrue(authentication.authorities.any { it.authority == "ROLE_ADMIN" })
        assertEquals(3L, chain.tenantIdDuringChain)
        assertEquals(1, sessionService.recordActivityCalls.size)
        assertEquals("session-7" to 7L, sessionService.recordActivityCalls.single())
        assertNull(TenantContextHolder.getTenantId())

        filter.doFilter(request, MockHttpServletResponse(), MockFilterChain())
        assertEquals(1, sessionService.recordActivityCalls.size)
    }

    @Test
    fun `failed token parse clears security and tenant context but still continues chain`() {
        val filter = JwtAuthenticationFilter(
            tokenService = object : TokenService {
                override fun generate(userPrincipal: UserPrincipal) = error("unused")
                override fun parse(accessToken: String): UserPrincipal = throw IllegalArgumentException("bad token")
                override fun refresh(refreshToken: String) = error("unused")
                override fun invalidate(accessToken: String) = Unit
            }
        )
        SecurityContextHolder.getContext().authentication =
            org.springframework.security.authentication.UsernamePasswordAuthenticationToken("stale", "stale")
        TenantContextHolder.setTenantId(99L)

        val request = MockHttpServletRequest().apply {
            addHeader(HttpHeaders.AUTHORIZATION, "Bearer bad-token")
        }
        val chain = CapturingFilterChain()

        filter.doFilter(request, MockHttpServletResponse(), chain)

        assertNull(chain.authentication)
        assertNull(chain.tenantIdDuringChain)
        assertNull(SecurityContextHolder.getContext().authentication)
        assertNull(TenantContextHolder.getTenantId())
    }

    @Test
    fun `stale tracked sessions are pruned during activity recording`() {
        val sessionService = RecordingSessionManagementService()
        val tokenService = RotatingTokenService(
            listOf(
                userPrincipal(sessionId = "session-a"),
                userPrincipal(sessionId = "session-b"),
                userPrincipal(sessionId = "session-a")
            )
        )
        val clock = MutableClock(Instant.parse("2026-04-17T00:00:00Z"), ZoneOffset.UTC)
        val filter = JwtAuthenticationFilter(
            tokenService = tokenService,
            sessionManagementService = sessionService,
            clock = clock,
            activityTouchIntervalSeconds = 1,
            trackedSessionRetentionSeconds = 2,
            trackedSessionPruneIntervalSeconds = 1,
            maxTrackedSessions = 1
        )

        val request = MockHttpServletRequest().apply {
            addHeader(HttpHeaders.AUTHORIZATION, "Bearer ok-token")
        }

        filter.doFilter(request, MockHttpServletResponse(), MockFilterChain())
        clock.advanceSeconds(3)
        filter.doFilter(request, MockHttpServletResponse(), MockFilterChain())
        clock.advanceSeconds(3)
        filter.doFilter(request, MockHttpServletResponse(), MockFilterChain())

        assertEquals(
            listOf("session-a", "session-b", "session-a"),
            sessionService.recordActivityCalls.map { it.first }
        )
        val trackedSessions = (filter as Any)::class.java
            .getDeclaredField("lastTouchedAtBySession")
            .apply { isAccessible = true }
            .get(filter) as Map<*, *>
        assertFalse(trackedSessions.containsKey("session-b"))
        assertTrue(trackedSessions.containsKey("session-a"))
    }
}

private class StaticTokenService(
    private val principal: UserPrincipal
) : TokenService {
    override fun generate(userPrincipal: UserPrincipal) = error("unused")
    override fun parse(accessToken: String): UserPrincipal = principal
    override fun refresh(refreshToken: String) = error("unused")
    override fun invalidate(accessToken: String) = Unit
}

private class RotatingTokenService(
    private val principals: List<UserPrincipal>
) : TokenService {
    private var index = 0

    override fun generate(userPrincipal: UserPrincipal) = error("unused")

    override fun parse(accessToken: String): UserPrincipal {
        val principal = principals[index.coerceAtMost(principals.lastIndex)]
        if (index < principals.lastIndex) {
            index += 1
        }
        return principal
    }

    override fun refresh(refreshToken: String) = error("unused")

    override fun invalidate(accessToken: String) = Unit
}

private class MutableClock(
    private var instant: Instant,
    private val zoneOffset: ZoneOffset
) : Clock() {
    override fun getZone() = zoneOffset
    override fun withZone(zone: java.time.ZoneId?): Clock = this
    override fun instant(): Instant = instant

    fun advanceSeconds(seconds: Long) {
        instant = instant.plusSeconds(seconds)
    }
}

private class CapturingFilterChain : MockFilterChain() {
    var authentication = null as org.springframework.security.core.Authentication?
    var tenantIdDuringChain: Long? = null

    override fun doFilter(request: jakarta.servlet.ServletRequest, response: jakarta.servlet.ServletResponse) {
        authentication = SecurityContextHolder.getContext().authentication
        tenantIdDuringChain = TenantContextHolder.getTenantId()
        (response as? HttpServletResponse)?.status = HttpServletResponse.SC_OK
    }
}

private class RecordingSessionManagementService : SessionManagementService {
    val recordActivityCalls = mutableListOf<Pair<String, Long>>()

    override fun openSession(command: SessionOpenCommand): SessionTokenContext =
        SessionTokenContext("session-7", SessionPolicyMode.MULTI_DEVICE)

    override fun touchSession(sessionId: String, userId: Long, accessExpireAtEpochSecond: Long, refreshExpireAtEpochSecond: Long): Boolean = true

    override fun recordSessionActivity(sessionId: String, userId: Long): Boolean {
        recordActivityCalls += sessionId to userId
        return true
    }

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

private fun userPrincipal(sessionId: String = "session-7"): UserPrincipal =
    UserPrincipal(
        userId = 7L,
        username = "tester",
        displayName = "Tester",
        status = UserStatus.ENABLED,
        groupId = 2L,
        tenantId = 3L,
        roles = setOf("ADMIN"),
        permissions = setOf("api:GET:/auth/me"),
        attributes = mapOf(
            "passwordVersion" to 1,
            "sessionId" to sessionId
        )
    )
