package org.sainm.auth.core.strategy

import org.sainm.auth.core.domain.UserPrincipal

interface PermissionStrategy {
    fun hasPermission(
        principal: UserPrincipal,
        permission: String,
        context: AuthorizationContext = AuthorizationContext()
    ): Boolean
}

data class AuthorizationContext(
    val tenantId: Long? = null,
    val groupId: Long? = null,
    val attributes: Map<String, Any?> = emptyMap()
)

class BasicPermissionStrategy : PermissionStrategy {
    override fun hasPermission(
        principal: UserPrincipal,
        permission: String,
        context: AuthorizationContext
    ): Boolean = principal.permissions.contains(permission)
}
