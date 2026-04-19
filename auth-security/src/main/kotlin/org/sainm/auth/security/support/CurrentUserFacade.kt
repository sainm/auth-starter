package org.sainm.auth.security.support

import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.exception.AuthenticatedUserNotFoundException
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.UserLookupService
import org.springframework.security.core.context.SecurityContextHolder

class CurrentUserFacade(
    private val userLookupService: UserLookupService,
    private val permissionService: PermissionService
) {

    fun requireCurrentUserId(): Long =
        (SecurityContextHolder.getContext().authentication?.principal as? Long)
            ?: throw AuthenticatedUserNotFoundException()

    fun requireCurrentUser(): UserPrincipal {
        val userId = requireCurrentUserId()
        val principal = userLookupService.findById(userId)
            ?: throw AuthenticatedUserNotFoundException()
        return principal.copy(
            roles = permissionService.loadRoles(userId),
            permissions = permissionService.loadPermissions(userId)
        )
    }
}
