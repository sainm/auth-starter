package org.sainm.auth.security.authz

import org.springframework.security.access.prepost.PreAuthorize

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
@MustBeDocumented
@PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, this.permission)")
annotation class RequirePermission(val permission: String)
