package org.sainm.auth.security.handler

import org.sainm.auth.core.domain.AuthResult
import org.sainm.auth.core.domain.LoginCommand
import org.sainm.auth.core.spi.AuthenticationHandler

class AuthenticationDispatcher(
    private val handlers: List<AuthenticationHandler<out LoginCommand>>
) {
    @Suppress("UNCHECKED_CAST")
    fun dispatch(command: LoginCommand): AuthResult {
        val handler = handlers.firstOrNull { it.supports(command) }
            ?: error("No AuthenticationHandler found for command: ${command::class.simpleName}")
        return (handler as AuthenticationHandler<LoginCommand>).authenticate(command)
    }
}
