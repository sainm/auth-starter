package org.sainm.auth.core.domain

data class UserPrincipal(
    val userId: Long,
    val username: String,
    val displayName: String?,
    val status: UserStatus,
    val groupId: Long?,
    val tenantId: Long?,
    val roles: Set<String> = emptySet(),
    val permissions: Set<String> = emptySet(),
    val attributes: Map<String, Any?> = emptyMap()
)

enum class UserStatus {
    ENABLED,
    DISABLED,
    LOCKED
}

sealed interface LoginCommand

data class PasswordLoginCommand(
    val principal: String,
    val password: String
) : LoginCommand

data class TokenPair(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long
)

data class AuthResult(
    val tokenPair: TokenPair,
    val user: UserPrincipal
)
