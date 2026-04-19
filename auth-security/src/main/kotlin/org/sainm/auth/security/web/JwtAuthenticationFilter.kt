package org.sainm.auth.security.web

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.sainm.auth.core.spi.SessionManagementService
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.security.context.TenantContextHolder
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Clock
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.ConcurrentHashMap

class JwtAuthenticationFilter(
    private val tokenService: TokenService,
    private val sessionManagementService: SessionManagementService? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val activityTouchIntervalSeconds: Long = 60,
    private val trackedSessionRetentionSeconds: Long = 3600,
    private val trackedSessionPruneIntervalSeconds: Long = 300,
    private val maxTrackedSessions: Int = 10_000
) : OncePerRequestFilter() {

    private val lastTouchedAtBySession = ConcurrentHashMap<String, Long>()
    private val lastPrunedAtEpochSecond = AtomicLong(0)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            val header = request.getHeader(HttpHeaders.AUTHORIZATION)
            if (header?.startsWith("Bearer ") == true) {
                val token = header.removePrefix("Bearer ").trim()
                val parsed = kotlin.runCatching {
                    val principal = tokenService.parse(token)
                    recordSessionActivityIfNeeded(principal)
                    val authorities = principal.roles.map { SimpleGrantedAuthority("ROLE_$it") }
                    val authentication = UsernamePasswordAuthenticationToken(principal.userId, principal, authorities)
                    SecurityContextHolder.getContext().authentication = authentication
                    TenantContextHolder.setTenantId(principal.tenantId)
                }
                if (parsed.isFailure) {
                    SecurityContextHolder.clearContext()
                    TenantContextHolder.clear()
                }
            }
            filterChain.doFilter(request, response)
        } finally {
            TenantContextHolder.clear()
        }
    }

    private fun recordSessionActivityIfNeeded(principal: org.sainm.auth.core.domain.UserPrincipal) {
        val sessionId = principal.attributes["sessionId"] as? String ?: return
        val now = clock.instant().epochSecond
        val minInterval = activityTouchIntervalSeconds.coerceAtLeast(1)
        pruneTrackedSessionsIfNeeded(now, minInterval)
        var shouldTouch = false
        lastTouchedAtBySession.compute(sessionId) { _, previous ->
            if (previous == null || now - previous >= minInterval) {
                shouldTouch = true
                now
            } else {
                previous
            }
        }
        if (shouldTouch) {
            val updated = sessionManagementService?.recordSessionActivity(sessionId, principal.userId) ?: true
            if (!updated) {
                lastTouchedAtBySession.remove(sessionId, now)
            }
        }
    }

    private fun pruneTrackedSessionsIfNeeded(now: Long, minInterval: Long) {
        val pruneInterval = trackedSessionPruneIntervalSeconds.coerceAtLeast(1)
        val shouldPruneByTime = now - lastPrunedAtEpochSecond.get() >= pruneInterval
        if (!shouldPruneByTime && lastTouchedAtBySession.size <= maxTrackedSessions) {
            return
        }
        if (!lastPrunedAtEpochSecond.compareAndSet(lastPrunedAtEpochSecond.get(), now) && lastTouchedAtBySession.size <= maxTrackedSessions) {
            return
        }
        val retentionSeconds = maxOf(trackedSessionRetentionSeconds.coerceAtLeast(minInterval), minInterval)
        val staleBefore = now - retentionSeconds
        lastTouchedAtBySession.entries.removeIf { (_, touchedAt) -> touchedAt < staleBefore }
    }
}
