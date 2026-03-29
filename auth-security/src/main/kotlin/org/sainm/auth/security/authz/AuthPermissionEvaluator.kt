package org.sainm.auth.security.authz

import org.sainm.auth.core.domain.UserPrincipal
import org.springframework.security.core.Authentication

class AuthPermissionEvaluator {

    fun hasPermission(authentication: Authentication?, permission: String): Boolean {
        if (authentication == null || !authentication.isAuthenticated) {
            return false
        }
        val user = authentication.credentials as? UserPrincipal ?: return false
        return permission in user.permissions
    }
}
