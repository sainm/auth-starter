package org.sainm.auth.security.handler

import org.sainm.auth.core.domain.PasswordLoginCommand
import org.sainm.auth.core.domain.TokenPair
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.exception.InvalidCredentialsException
import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.core.spi.LoginAttemptResult
import org.sainm.auth.core.spi.LoginAttemptService
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserCredentialView
import org.sainm.auth.core.spi.UserLookupService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PasswordAuthenticationHandlerTest {

    private val passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
    private val basePrincipal = UserPrincipal(
        userId = 1L,
        username = "admin",
        displayName = "系统管理员",
        status = UserStatus.ENABLED,
        groupId = 1L,
        tenantId = 1L
    )

    @Test
    fun `successful login enriches principal and writes success audit`() {
        val auditPublisher = RecordingAuditEventPublisher()
        val handler = PasswordAuthenticationHandler(
            userLookupService = object : UserLookupService {
                override fun findById(userId: Long): UserPrincipal? = null

                override fun findByPrincipal(principal: String): UserCredentialView =
                    UserCredentialView(basePrincipal, passwordEncoder.encode("P@ssw0rd!"))
            },
            permissionService = object : PermissionService {
                override fun loadPermissions(userId: Long): Set<String> = setOf("api:GET:/auth/me")
                override fun loadRoles(userId: Long): Set<String> = setOf("ADMIN")
            },
            tokenService = object : TokenService {
                override fun generate(userPrincipal: UserPrincipal): TokenPair =
                    TokenPair("access", "refresh", "Bearer", 1800)

                override fun parse(accessToken: String): UserPrincipal = error("unused")
                override fun refresh(refreshToken: String): TokenPair = error("unused")
                override fun invalidate(accessToken: String) = Unit
            },
            passwordEncoder = passwordEncoder,
            auditEventPublisher = auditPublisher,
            loginAttemptService = NoopLoginAttemptService()
        )

        val result = handler.authenticate(PasswordLoginCommand("admin", "P@ssw0rd!"))

        assertEquals(setOf("ADMIN"), result.user.roles)
        assertEquals(setOf("api:GET:/auth/me"), result.user.permissions)
        assertEquals("LOGIN_SUCCESS", auditPublisher.events.single().type)
    }

    @Test
    fun `bad password writes fail audit and throws`() {
        val auditPublisher = RecordingAuditEventPublisher()
        val handler = PasswordAuthenticationHandler(
            userLookupService = object : UserLookupService {
                override fun findById(userId: Long): UserPrincipal? = null

                override fun findByPrincipal(principal: String): UserCredentialView =
                    UserCredentialView(basePrincipal, passwordEncoder.encode("P@ssw0rd!"))
            },
            permissionService = object : PermissionService {
                override fun loadPermissions(userId: Long): Set<String> = emptySet()
                override fun loadRoles(userId: Long): Set<String> = emptySet()
            },
            tokenService = object : TokenService {
                override fun generate(userPrincipal: UserPrincipal): TokenPair = error("unused")
                override fun parse(accessToken: String): UserPrincipal = error("unused")
                override fun refresh(refreshToken: String): TokenPair = error("unused")
                override fun invalidate(accessToken: String) = Unit
            },
            passwordEncoder = passwordEncoder,
            auditEventPublisher = auditPublisher,
            loginAttemptService = NoopLoginAttemptService()
        )

        assertFailsWith<InvalidCredentialsException> {
            handler.authenticate(PasswordLoginCommand("admin", "wrong"))
        }

        assertEquals("LOGIN_FAIL", auditPublisher.events.single().type)
        assertEquals("bad_credentials", auditPublisher.events.single().detail["reason"])
    }
}

private class NoopLoginAttemptService : LoginAttemptService {
    override fun resetAttempts(userId: Long) = Unit

    override fun recordFailure(principal: String): LoginAttemptResult =
        LoginAttemptResult(locked = false, remainingAttempts = 4, lockedUntilEpochSecond = null)
}

private class RecordingAuditEventPublisher : AuditEventPublisher {
    val events = mutableListOf<AuditEvent>()

    override fun publish(event: AuditEvent) {
        events += event
    }
}
