package org.sainm.auth.security.web

import jakarta.validation.Valid
import org.sainm.auth.core.domain.PasswordLoginCommand
import org.sainm.auth.core.exception.AuthenticatedUserNotFoundException
import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.core.spi.AuditQueryService
import org.sainm.auth.core.spi.ChangePasswordCommand
import org.sainm.auth.core.spi.CreateGroupCommand
import org.sainm.auth.core.spi.CreateTenantCommand
import org.sainm.auth.core.spi.GroupRoleAssignmentCommand
import org.sainm.auth.core.spi.OrganizationService
import org.sainm.auth.core.spi.PasswordManagementService
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.QrLoginService
import org.sainm.auth.core.spi.ResetPasswordCommand
import org.sainm.auth.core.spi.RoleAssignmentCommand
import org.sainm.auth.core.spi.SocialLoginService
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserAdminService
import org.sainm.auth.core.spi.UserLookupService
import org.sainm.auth.core.spi.UserRegistrationCommand
import org.sainm.auth.core.spi.UserRegistrationService
import org.sainm.auth.security.api.ApiResponse
import org.sainm.auth.security.api.AuthResponse
import org.sainm.auth.security.api.ChangePasswordRequest
import org.sainm.auth.security.api.CreateGroupRequest
import org.sainm.auth.security.api.CreateTenantRequest
import org.sainm.auth.security.api.GroupRoleAssignRequest
import org.sainm.auth.security.api.LogoutRequest
import org.sainm.auth.security.api.PasswordLoginRequest
import org.sainm.auth.security.api.QrCancelRequest
import org.sainm.auth.security.api.QrConfirmRequest
import org.sainm.auth.security.api.QrScanRequest
import org.sainm.auth.security.api.QrSceneResponse
import org.sainm.auth.security.api.RefreshTokenRequest
import org.sainm.auth.security.api.RegisterRequest
import org.sainm.auth.security.api.RegisterResponse
import org.sainm.auth.security.api.ResetPasswordRequest
import org.sainm.auth.security.api.RoleAssignRequest
import org.sainm.auth.security.api.SocialLoginRequest
import org.sainm.auth.security.handler.AuthenticationDispatcher
import org.springframework.beans.factory.ObjectProvider
import org.springframework.http.HttpHeaders
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.context.request.RequestAttributes
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class AuthController(
    private val authenticationDispatcher: AuthenticationDispatcher,
    private val userLookupService: UserLookupService,
    private val permissionService: PermissionService,
    private val tokenService: TokenService,
    private val userRegistrationService: UserRegistrationService,
    private val passwordManagementService: PasswordManagementService,
    private val auditEventPublisher: AuditEventPublisher,
    private val auditQueryService: AuditQueryService,
    private val userAdminService: UserAdminService,
    private val organizationService: OrganizationService,
    private val qrLoginServiceProvider: ObjectProvider<QrLoginService>,
    private val socialLoginServiceProvider: ObjectProvider<SocialLoginService>
) {

    @PostMapping("/login/password")
    fun passwordLogin(@Valid @RequestBody request: PasswordLoginRequest): ApiResponse<AuthResponse> {
        val result = authenticationDispatcher.dispatch(
            PasswordLoginCommand(
                principal = request.principal,
                password = request.password
            )
        )
        return ApiResponse.ok(
            AuthResponse(
                accessToken = result.tokenPair.accessToken,
                refreshToken = result.tokenPair.refreshToken,
                tokenType = result.tokenPair.tokenType,
                expiresIn = result.tokenPair.expiresIn,
                user = result.user
            )
        )
    }

    @PostMapping("/social/google")
    fun googleLogin(@Valid @RequestBody request: SocialLoginRequest): ApiResponse<AuthResponse> =
        ApiResponse.ok(buildAuthResponse(enrichUser(socialLoginService().authenticate("GOOGLE", request.authCode).userId)))

    @PostMapping("/social/google/mock")
    fun googleMockLogin(@Valid @RequestBody request: SocialLoginRequest): ApiResponse<AuthResponse> =
        googleLogin(request)

    @PostMapping("/social/wechat")
    fun wechatLogin(@Valid @RequestBody request: SocialLoginRequest): ApiResponse<AuthResponse> =
        ApiResponse.ok(buildAuthResponse(enrichUser(socialLoginService().authenticate("WECHAT", request.authCode).userId)))

    @PostMapping("/social/wechat/mock")
    fun wechatMockLogin(@Valid @RequestBody request: SocialLoginRequest): ApiResponse<AuthResponse> =
        wechatLogin(request)

    @PostMapping("/qr/scene")
    fun createQrScene(): ApiResponse<QrSceneResponse> =
        ApiResponse.ok(qrLoginService().createScene().toResponse())

    @GetMapping("/qr/scene/{sceneCode}")
    fun getQrScene(@PathVariable sceneCode: String): ApiResponse<QrSceneResponse> {
        val consumed = qrLoginService().consumeScene(sceneCode)
        if (consumed != null) {
            val user = enrichUser(consumed.user.userId)
            auditEventPublisher.publish(
                AuditEvent(
                    type = "QR_CONSUMED",
                    userId = consumed.user.userId,
                    principal = consumed.user.username,
                    detail = mapOf("sceneCode" to sceneCode)
                )
            )
            return ApiResponse.ok(
                consumed.scene.toResponse(
                    auth = buildAuthResponse(user)
                )
            )
        }

        val scene = qrLoginService().getScene(sceneCode) ?: throw IllegalArgumentException("auth.qr.scene.notFound")
        return ApiResponse.ok(scene.toResponse())
    }

    @PostMapping("/qr/scan")
    fun scanQrScene(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: QrScanRequest
    ): ApiResponse<QrSceneResponse> {
        val principal = userId ?: throw AuthenticatedUserNotFoundException()
        val scene = qrLoginService().scanScene(request.sceneCode, principal)
        val user = enrichUser(principal)
        auditEventPublisher.publish(
            AuditEvent(
                type = "QR_SCANNED",
                userId = principal,
                principal = user.username,
                detail = mapOf("sceneCode" to request.sceneCode)
            )
        )
        return ApiResponse.ok(scene.toResponse())
    }

    @PostMapping("/qr/confirm")
    fun confirmQrScene(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: QrConfirmRequest
    ): ApiResponse<QrSceneResponse> {
        val principal = userId ?: throw AuthenticatedUserNotFoundException()
        val scene = qrLoginService().confirmScene(request.sceneCode, principal)
        val user = enrichUser(principal)
        auditEventPublisher.publish(
            AuditEvent(
                type = "QR_CONFIRMED",
                userId = principal,
                principal = user.username,
                detail = mapOf("sceneCode" to request.sceneCode)
            )
        )
        return ApiResponse.ok(scene.toResponse())
    }

    @PostMapping("/qr/cancel")
    fun cancelQrScene(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: QrCancelRequest
    ): ApiResponse<QrSceneResponse> {
        val scene = qrLoginService().cancelScene(request.sceneCode, userId)
        val username = userId?.let { enrichUser(it).username }
        auditEventPublisher.publish(
            AuditEvent(
                type = "QR_CANCELED",
                userId = userId,
                principal = username,
                detail = mapOf("sceneCode" to request.sceneCode)
            )
        )
        return ApiResponse.ok(scene.toResponse())
    }

    @PostMapping("/token/refresh")
    fun refreshToken(@Valid @RequestBody request: RefreshTokenRequest): ApiResponse<Map<String, Any>> {
        val tokenPair = tokenService.refresh(request.refreshToken)
        return ApiResponse.ok(
            mapOf(
                "accessToken" to tokenPair.accessToken,
                "refreshToken" to tokenPair.refreshToken,
                "tokenType" to tokenPair.tokenType,
                "expiresIn" to tokenPair.expiresIn
            )
        )
    }

    @PostMapping("/logout")
    fun logout(
        @Valid @RequestBody request: LogoutRequest,
        @RequestHeader(HttpHeaders.AUTHORIZATION, required = false) authorization: String?
    ): ApiResponse<Boolean> {
        authorization
            ?.takeIf { it.startsWith("Bearer ") }
            ?.removePrefix("Bearer ")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.let(tokenService::invalidate)
        tokenService.invalidate(request.refreshToken)
        return ApiResponse.ok(true)
    }

    @PostMapping("/register")
    fun register(@Valid @RequestBody request: RegisterRequest): ApiResponse<RegisterResponse> {
        val result = userRegistrationService.register(
            UserRegistrationCommand(
                username = request.username,
                password = request.password,
                email = request.email,
                mobile = request.mobile,
                displayName = request.displayName
            )
        )
        return ApiResponse.ok(
            RegisterResponse(
                userId = result.userId,
                username = result.username,
                defaultRoles = result.defaultRoles
            )
        )
    }

    @PostMapping("/password/change")
    fun changePassword(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: ChangePasswordRequest
    ): ApiResponse<Boolean> {
        passwordManagementService.changePassword(
            ChangePasswordCommand(
                userId = userId ?: throw AuthenticatedUserNotFoundException(),
                oldPassword = request.oldPassword,
                newPassword = request.newPassword
            )
        )
        val user = enrichUser(userId)
        auditEventPublisher.publish(
            AuditEvent(
                type = "PASSWORD_CHANGED",
                userId = userId,
                principal = user.username
            )
        )
        return ApiResponse.ok(true)
    }

    @PostMapping("/password/reset")
    fun resetPassword(@Valid @RequestBody request: ResetPasswordRequest): ApiResponse<Boolean> {
        passwordManagementService.resetPassword(
            ResetPasswordCommand(
                principal = request.principal,
                newPassword = request.newPassword
            )
        )
        auditEventPublisher.publish(
            AuditEvent(
                type = "PASSWORD_RESET",
                principal = request.principal
            )
        )
        return ApiResponse.ok(true)
    }

    @GetMapping("/me")
    fun me(@AuthenticationPrincipal userId: Long?): ApiResponse<Any> =
        ApiResponse.ok(enrichUser(userId ?: throw AuthenticatedUserNotFoundException()))

    @GetMapping("/admin/ping")
    fun adminPing(): ApiResponse<Map<String, Boolean>> = ApiResponse.ok(mapOf("ok" to true))

    @GetMapping("/users")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:GET:/auth/users')")
    fun users(
        @AuthenticationPrincipal principalUserId: Long?,
        @RequestParam(defaultValue = "1") page: Int,
        @RequestParam(defaultValue = "20") size: Int,
        @RequestParam(required = false) tenantId: Long?
    ): ApiResponse<Any> = ApiResponse.ok(userAdminService.listUsers(page, size, scopedTenantId(principalUserId, tenantId)))

    @GetMapping("/roles")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:GET:/auth/roles')")
    fun roles(
        @AuthenticationPrincipal principalUserId: Long?,
        @RequestParam(required = false) tenantId: Long?
    ): ApiResponse<Any> = ApiResponse.ok(userAdminService.listRoles(scopedTenantId(principalUserId, tenantId)))

    @GetMapping("/permissions")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:GET:/auth/permissions')")
    fun permissions(
        @AuthenticationPrincipal principalUserId: Long?,
        @RequestParam(required = false) tenantId: Long?
    ): ApiResponse<Any> = ApiResponse.ok(userAdminService.listPermissions(scopedTenantId(principalUserId, tenantId)))

    @PostMapping("/users/{userId}/roles")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:POST:/auth/users/roles')")
    fun assignRoles(
        @PathVariable userId: Long,
        @Valid @RequestBody request: RoleAssignRequest
    ): ApiResponse<Any> =
        ApiResponse.ok(userAdminService.assignRoles(RoleAssignmentCommand(userId, request.roleCodes)))

    @PostMapping("/groups/{groupId}/roles")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:POST:/auth/groups/roles')")
    fun assignGroupRoles(
        @PathVariable groupId: Long,
        @Valid @RequestBody request: GroupRoleAssignRequest
    ): ApiResponse<Any> =
        ApiResponse.ok(organizationService.assignGroupRoles(GroupRoleAssignmentCommand(groupId, request.roleCodes)))

    @GetMapping("/tenants")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:GET:/auth/tenants')")
    fun tenants(
        @AuthenticationPrincipal principalUserId: Long?,
        @RequestParam(required = false) tenantId: Long?
    ): ApiResponse<Any> = ApiResponse.ok(organizationService.listTenants(scopedTenantId(principalUserId, tenantId)))

    @PostMapping("/tenants")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:POST:/auth/tenants')")
    fun createTenant(@Valid @RequestBody request: CreateTenantRequest): ApiResponse<Any> =
        ApiResponse.ok(
            organizationService.createTenant(
                CreateTenantCommand(
                    tenantCode = request.tenantCode,
                    tenantName = request.tenantName
                )
            )
        )

    @GetMapping("/groups")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:GET:/auth/groups')")
    fun groups(
        @AuthenticationPrincipal principalUserId: Long?,
        @RequestParam(required = false) tenantId: Long?
    ): ApiResponse<Any> = ApiResponse.ok(organizationService.listGroups(scopedTenantId(principalUserId, tenantId)))

    @PostMapping("/groups")
    @PreAuthorize("@authPermissionEvaluator.hasPermission(authentication, 'api:POST:/auth/groups')")
    fun createGroup(
        @AuthenticationPrincipal principalUserId: Long?,
        @Valid @RequestBody request: CreateGroupRequest
    ): ApiResponse<Any> =
        ApiResponse.ok(
            organizationService.createGroup(
                CreateGroupCommand(
                    groupCode = request.groupCode,
                    groupName = request.groupName,
                    tenantId = scopedTenantId(principalUserId, request.tenantId),
                    parentId = request.parentId
                )
            )
        )

    @GetMapping("/login-logs")
    fun loginLogs(
        @RequestParam(defaultValue = "1") page: Int,
        @RequestParam(defaultValue = "20") size: Int,
        @RequestParam(required = false) principal: String?,
        @RequestParam(required = false) result: String?
    ): ApiResponse<Any> =
        ApiResponse.ok(auditQueryService.findLoginLogs(page, size, principal, result))

    @GetMapping("/security-events")
    fun securityEvents(
        @RequestParam(defaultValue = "1") page: Int,
        @RequestParam(defaultValue = "20") size: Int,
        @RequestParam(required = false) eventType: String?
    ): ApiResponse<Any> =
        ApiResponse.ok(auditQueryService.findSecurityEvents(page, size, eventType))

    private fun enrichUser(userId: Long) =
        requestUserCache()[userId]
            ?: loadEnrichedUser(userId).also { requestUserCache()[userId] = it }

    private fun loadEnrichedUser(userId: Long) =
        userLookupService.findById(userId)
            ?.copy(
                roles = permissionService.loadRoles(userId),
                permissions = permissionService.loadPermissions(userId)
            )
            ?: throw AuthenticatedUserNotFoundException()

    private fun buildAuthResponse(user: org.sainm.auth.core.domain.UserPrincipal): AuthResponse {
        val tokenPair = tokenService.generate(user)
        return AuthResponse(
            accessToken = tokenPair.accessToken,
            refreshToken = tokenPair.refreshToken,
            tokenType = tokenPair.tokenType,
            expiresIn = tokenPair.expiresIn,
            user = user
        )
    }

    private fun qrLoginService(): QrLoginService =
        qrLoginServiceProvider.ifAvailable ?: throw IllegalArgumentException("auth.qr.disabled")

    private fun socialLoginService(): SocialLoginService =
        socialLoginServiceProvider.ifAvailable ?: throw IllegalArgumentException("auth.social.disabled")

    private fun scopedTenantId(principalUserId: Long?, requestedTenantId: Long?): Long? {
        val principal = principalUserId?.let(::enrichUser) ?: return requestedTenantId
        return if ("SUPER_ADMIN" in principal.roles) requestedTenantId else principal.tenantId
    }

    @Suppress("UNCHECKED_CAST")
    private fun requestUserCache(): MutableMap<Long, org.sainm.auth.core.domain.UserPrincipal> {
        val requestAttributes = RequestContextHolder.getRequestAttributes() as? ServletRequestAttributes
        if (requestAttributes == null) {
            return mutableMapOf()
        }

        val existing = requestAttributes.getAttribute(USER_CACHE_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST)
            as? MutableMap<Long, org.sainm.auth.core.domain.UserPrincipal>
        if (existing != null) {
            return existing
        }

        val created = mutableMapOf<Long, org.sainm.auth.core.domain.UserPrincipal>()
        requestAttributes.setAttribute(USER_CACHE_ATTRIBUTE, created, RequestAttributes.SCOPE_REQUEST)
        return created
    }

    private fun org.sainm.auth.core.spi.QrSceneSummary.toResponse(auth: AuthResponse? = null) =
        QrSceneResponse(
            sceneCode = sceneCode,
            status = status,
            expiresAt = expiresAtEpochSecond,
            scannedUserId = scannedUserId,
            approvedUserId = approvedUserId,
            auth = auth
        )

    companion object {
        private const val USER_CACHE_ATTRIBUTE = "auth.enrichedUsers"
    }
}
