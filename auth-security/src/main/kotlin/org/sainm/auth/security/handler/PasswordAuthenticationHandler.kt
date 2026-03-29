package org.sainm.auth.security.handler

import org.sainm.auth.core.domain.AuthResult
import org.sainm.auth.core.domain.LoginCommand
import org.sainm.auth.core.domain.PasswordLoginCommand
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.exception.AccountLockedException
import org.sainm.auth.core.exception.InvalidCredentialsException
import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.core.spi.AuthenticationHandler
import org.sainm.auth.core.spi.LoginAttemptService
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserLookupService
import org.springframework.security.crypto.password.PasswordEncoder

class PasswordAuthenticationHandler(
    private val userLookupService: UserLookupService,
    private val permissionService: PermissionService,
    private val tokenService: TokenService,
    private val passwordEncoder: PasswordEncoder,
    private val auditEventPublisher: AuditEventPublisher,
    private val loginAttemptService: LoginAttemptService
) : AuthenticationHandler<PasswordLoginCommand> {

    override fun supports(command: LoginCommand): Boolean = command is PasswordLoginCommand

    override fun authenticate(command: PasswordLoginCommand): AuthResult {
        val credentialView = userLookupService.findByPrincipal(command.principal)
            ?: run {
                loginAttemptService.recordFailure(command.principal)
                auditEventPublisher.publish(
                    AuditEvent(
                        type = "LOGIN_FAIL",
                        principal = command.principal,
                        detail = mapOf("reason" to "bad_credentials", "loginType" to "PASSWORD")
                    )
                )
                throw InvalidCredentialsException()
            }

        if (credentialView.principal.status == UserStatus.LOCKED) {
            auditEventPublisher.publish(
                AuditEvent(
                    type = "ACCOUNT_LOCKED",
                    userId = credentialView.principal.userId,
                    principal = credentialView.principal.username,
                    detail = mapOf("reason" to "locked", "loginType" to "PASSWORD")
                )
            )
            throw AccountLockedException()
        }
        val passwordHash = credentialView.passwordHash
            ?: run {
                loginAttemptService.recordFailure(command.principal)
                auditEventPublisher.publish(
                    AuditEvent(
                        type = "LOGIN_FAIL",
                        principal = command.principal,
                        detail = mapOf("reason" to "password_missing", "loginType" to "PASSWORD")
                    )
                )
                throw InvalidCredentialsException()
            }

        if (!passwordEncoder.matches(command.password, passwordHash)) {
            val attemptResult = loginAttemptService.recordFailure(command.principal)
            auditEventPublisher.publish(
                AuditEvent(
                    type = "LOGIN_FAIL",
                    principal = command.principal,
                    detail = mapOf(
                        "reason" to "bad_credentials",
                        "loginType" to "PASSWORD",
                        "locked" to attemptResult.locked,
                        "remainingAttempts" to attemptResult.remainingAttempts,
                        "lockedUntil" to attemptResult.lockedUntilEpochSecond
                    )
                )
            )
            if (attemptResult.locked) {
                auditEventPublisher.publish(
                    AuditEvent(
                        type = "ACCOUNT_LOCKED",
                        userId = credentialView.principal.userId,
                        principal = credentialView.principal.username,
                        detail = mapOf(
                            "reason" to "max_attempts_exceeded",
                            "lockedUntil" to attemptResult.lockedUntilEpochSecond
                        )
                    )
                )
                throw AccountLockedException()
            }
            throw InvalidCredentialsException()
        }

        loginAttemptService.resetAttempts(credentialView.principal.userId)
        val user = credentialView.principal.copy(
            roles = permissionService.loadRoles(credentialView.principal.userId),
            permissions = permissionService.loadPermissions(credentialView.principal.userId)
        )
        val tokenPair = tokenService.generate(user)

        auditEventPublisher.publish(
            AuditEvent(
                type = "LOGIN_SUCCESS",
                userId = user.userId,
                principal = user.username,
                detail = mapOf("loginType" to "PASSWORD")
            )
        )

        return AuthResult(tokenPair = tokenPair, user = user)
    }
}
