package org.sainm.auth.security.web

import jakarta.validation.Valid
import jakarta.servlet.http.HttpServletRequest
import org.sainm.auth.core.domain.PasswordLoginCommand
import org.sainm.auth.core.exception.AuthenticatedUserNotFoundException
import org.sainm.auth.core.spi.SessionManagementService
import org.sainm.auth.core.spi.SessionPolicyMode
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
import org.sainm.auth.core.spi.EmailVerificationService
import org.sainm.auth.core.spi.MailSenderService
import org.sainm.auth.core.spi.SocialLoginService
import org.sainm.auth.core.spi.SsoAuthProvider
import org.sainm.auth.core.spi.SsoAuthorizationRequest
import org.sainm.auth.core.spi.SsoCallback
import org.sainm.auth.core.spi.SsoState
import org.sainm.auth.core.spi.SsoStateStore
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserAdminService
import org.sainm.auth.core.spi.UserLookupService
import org.sainm.auth.core.spi.UserRegistrationCommand
import org.sainm.auth.core.spi.UserRegistrationService
import org.sainm.auth.security.api.ApiResponse
import org.sainm.auth.security.api.AuthResponse
import org.sainm.auth.security.api.ChangePasswordRequest
import org.sainm.auth.security.api.CurrentUserProfileResponse
import org.sainm.auth.security.api.CreateGroupRequest
import org.sainm.auth.security.api.CreateTenantRequest
import org.sainm.auth.security.api.GroupRoleAssignRequest
import org.sainm.auth.security.api.LogoutRequest
import org.sainm.auth.security.api.LoginActivityResponse
import org.sainm.auth.security.api.PasswordLoginRequest
import org.sainm.auth.security.api.QrCancelRequest
import org.sainm.auth.security.api.QrConfirmRequest
import org.sainm.auth.security.api.QrScanRequest
import org.sainm.auth.security.api.QrSceneResponse
import org.sainm.auth.security.api.RegistrationOptionsResponse
import org.sainm.auth.security.api.RefreshTokenRequest
import org.sainm.auth.security.api.RegisterRequest
import org.sainm.auth.security.api.RegisterResponse
import org.sainm.auth.security.api.ExternalRegisterRequest
import org.sainm.auth.security.api.ResendActivationRequest
import org.sainm.auth.security.api.ResetPasswordRequest
import org.sainm.auth.security.api.RoleAssignRequest
import org.sainm.auth.security.api.SecurityEventResponse
import org.sainm.auth.security.api.SessionPolicyResponse
import org.sainm.auth.security.api.SessionRevokeResponse
import org.sainm.auth.security.api.SessionSummaryResponse
import org.sainm.auth.security.api.SocialLoginRequest
import org.sainm.auth.security.api.SsoTicketExchangeRequest
import org.sainm.auth.security.api.UpdateSessionPolicyRequest
import org.sainm.auth.security.handler.AuthenticationDispatcher
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import java.net.URI
import java.util.UUID
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.context.SecurityContextHolder
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
    private val sessionManagementServiceProvider: ObjectProvider<SessionManagementService>,
    private val qrLoginServiceProvider: ObjectProvider<QrLoginService>,
    private val socialLoginServiceProvider: ObjectProvider<SocialLoginService>,
    private val ssoStateStoreProvider: ObjectProvider<SsoStateStore>,
    private val ssoAuthProviders: ObjectProvider<SsoAuthProvider>,
    private val emailVerificationService: ObjectProvider<EmailVerificationService>,
    private val mailSenderService: ObjectProvider<MailSenderService>,
    @Value("\${auth-module.registration.self-service-enabled:false}")
    private val selfRegistrationEnabled: Boolean,
    @Value("\${auth-module.security.password.min-length:8}")
    private val passwordMinLength: Int,
    @Value("\${auth-module.sso.callback-base-url:}")
    private val ssoCallbackBaseUrl: String,
    @Value("\${auth-module.sso.frontend-callback-url:}")
    private val ssoFrontendCallbackUrl: String,
    @Value("\${auth-module.sso.state-ttl-seconds:300}")
    private val ssoStateTtlSeconds: Long,
    @Value("\${auth-module.sso.ticket-ttl-seconds:120}")
    private val ssoTicketTtlSeconds: Long,
    @Value("\${auth-module.email.verify-token-ttl-seconds:86400}")
    private val emailVerifyTokenTtlSeconds: Long,
    @Value("\${auth-module.email.activation-subject:Activate your account}")
    private val emailActivationSubject: String,
    @Value("\${auth-module.email.activation-base-url:}")
    private val emailActivationBaseUrl: String
) {

    @PostMapping("/login/password")
    fun passwordLogin(
        @Valid @RequestBody request: PasswordLoginRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<AuthResponse> {
        val result = authenticationDispatcher.dispatch(
            PasswordLoginCommand(
                principal = request.principal,
                password = request.password
            )
        )
        return ApiResponse.ok(
            buildAuthResponse(
                result.user,
                servletRequest,
                request.clientId,
                request.deviceId,
                request.deviceType,
                request.deviceName
            )
        )
    }

    @PostMapping("/social/google")
    fun googleLogin(
        @Valid @RequestBody request: SocialLoginRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<AuthResponse> {
        val user = socialAuthenticate("GOOGLE", request.authCode, servletRequest)
        return ApiResponse.ok(
            buildAuthResponse(
                user,
                servletRequest,
                request.clientId,
                request.deviceId,
                request.deviceType,
                request.deviceName
            )
        )
    }

    @PostMapping("/social/google/mock")
    fun googleMockLogin(
        @Valid @RequestBody request: SocialLoginRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<AuthResponse> =
        googleLogin(request, servletRequest)

    @PostMapping("/social/wechat")
    fun wechatLogin(
        @Valid @RequestBody request: SocialLoginRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<AuthResponse> {
        val user = socialAuthenticate("WECHAT", request.authCode, servletRequest)
        return ApiResponse.ok(
            buildAuthResponse(
                user,
                servletRequest,
                request.clientId,
                request.deviceId,
                request.deviceType,
                request.deviceName
            )
        )
    }

    @PostMapping("/social/wechat/mock")
    fun wechatMockLogin(
        @Valid @RequestBody request: SocialLoginRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<AuthResponse> =
        wechatLogin(request, servletRequest)

    /**
     * Start an SSO (CAS/OIDC) login: generate anti-forgery state/nonce, persist
     * it, and redirect the browser to the identity provider authorization URL.
     */
    @GetMapping("/sso/{provider}/authorize")
    fun ssoAuthorize(
        @PathVariable provider: String,
        @RequestParam(required = false) returnTo: String?
    ): org.springframework.http.ResponseEntity<Void> {
        val normalized = provider.uppercase()
        val ssoProvider = ssoProvider(normalized)
        val redirectUri = ssoRedirectUri(normalized)
        val state = java.util.UUID.randomUUID().toString().replace("-", "")
        val nonce = java.util.UUID.randomUUID().toString().replace("-", "")
        ssoStateStore().save(
            SsoState(
                stateKey = state,
                provider = normalized,
                nonce = nonce,
                redirectUri = redirectUri,
                returnTo = returnTo?.takeIf { it.isNotBlank() }
            ),
            ssoStateTtlSeconds
        )
        val authorizationUrl = ssoProvider.buildAuthorizationUrl(
            SsoAuthorizationRequest(
                state = state,
                nonce = nonce,
                redirectUri = redirectUri,
                returnTo = returnTo
            )
        )
        return org.springframework.http.ResponseEntity
            .status(org.springframework.http.HttpStatus.FOUND)
            .location(java.net.URI.create(authorizationUrl))
            .build()
    }

    /**
     * SSO callback endpoint. OIDC calls back with `code`+`state`, CAS with
     * `ticket`+ the original service (which equals our redirect URI). We validate
     * state, resolve the identity, ensure a local user, then hand a short-lived
     * one-time ticket back to the frontend via redirect so tokens never appear
     * in a URL.
     */
    @GetMapping("/sso/{provider}/callback")
    fun ssoCallback(
        @PathVariable provider: String,
        @RequestParam(required = false) code: String?,
        @RequestParam(required = false) ticket: String?,
        @RequestParam(required = false) state: String?,
        servletRequest: HttpServletRequest
    ): org.springframework.http.ResponseEntity<Void> {
        val normalized = provider.uppercase()
        val ssoProvider = ssoProvider(normalized)
        val authCode = (code ?: ticket)?.trim()
            ?: throw IllegalArgumentException("auth.sso.callback.code.missing")

        // CAS does not echo our state param; OIDC does. When present it must match.
        val savedState = state?.takeIf { it.isNotBlank() }?.let { ssoStateStore().consume(it) }
        if (state != null && state.isNotBlank() && savedState == null) {
            throw IllegalArgumentException("auth.sso.state.invalid")
        }
        val redirectUri = savedState?.redirectUri ?: ssoRedirectUri(normalized)

        val identity = ssoProvider.resolve(
            SsoCallback(
                authCode = authCode,
                state = state,
                nonce = savedState?.nonce,
                redirectUri = redirectUri
            )
        )
        val user = runCatching {
            enrichUser(socialLoginService().authenticate(normalized,
                SsoCallback(authCode = authCode, state = state, nonce = savedState?.nonce, redirectUri = redirectUri)
            ).userId)
        }.onSuccess { resolved ->
            auditEventPublisher.publish(
                AuditEvent(
                    type = "LOGIN_SUCCESS",
                    userId = resolved.userId,
                    principal = resolved.username,
                    ip = clientIp(servletRequest),
                    userAgent = clientUserAgent(servletRequest),
                    detail = mapOf("loginType" to normalized)
                )
            )
        }.onFailure { error ->
            auditEventPublisher.publish(
                AuditEvent(
                    type = "LOGIN_FAIL",
                    principal = normalized.lowercase(),
                    ip = clientIp(servletRequest),
                    userAgent = clientUserAgent(servletRequest),
                    detail = mapOf(
                        "loginType" to normalized,
                        "reason" to (error.message ?: "sso_auth_failed")
                    )
                )
            )
        }.getOrThrow()

        // One-time ticket -> frontend exchanges it for real tokens.
        val exchangeTicket = java.util.UUID.randomUUID().toString().replace("-", "")
        ssoStateStore().save(
            SsoState(
                stateKey = exchangeTicket,
                provider = normalized,
                userId = user.userId
            ),
            ssoTicketTtlSeconds
        )
        val frontend = savedState?.returnTo?.takeIf { it.isNotBlank() } ?: ssoFrontendCallbackUrl
        require(frontend.isNotBlank()) { "auth.sso.frontendCallbackUrl.missing" }
        val target = frontend + (if (frontend.contains('?')) "&" else "?") + "ticket=" + exchangeTicket
        return org.springframework.http.ResponseEntity
            .status(org.springframework.http.HttpStatus.FOUND)
            .location(java.net.URI.create(target))
            .build()
    }

    /** Exchange the one-time SSO ticket for a real token pair. */
    @PostMapping("/sso/token")
    fun ssoTokenExchange(
        @Valid @RequestBody request: SsoTicketExchangeRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<AuthResponse> {
        val state = ssoStateStore().consume(request.ticket.trim())
            ?: throw IllegalArgumentException("auth.sso.ticket.invalid")
        val userId = state.userId ?: throw IllegalArgumentException("auth.sso.ticket.invalid")
        val user = enrichUser(userId)
        return ApiResponse.ok(
            buildAuthResponse(
                user,
                servletRequest,
                request.clientId,
                request.deviceId,
                request.deviceType,
                request.deviceName
            )
        )
    }

    @PostMapping("/qr/scene")
    fun createQrScene(): ApiResponse<QrSceneResponse> =
        ApiResponse.ok(qrLoginService().createScene().toResponse())

    @GetMapping("/qr/scene/{sceneCode}")
    fun getQrScene(
        @PathVariable sceneCode: String,
        servletRequest: HttpServletRequest
    ): ApiResponse<QrSceneResponse> {
        val consumed = qrLoginService().consumeScene(sceneCode)
        if (consumed != null) {
            val user = enrichUser(consumed.user.userId)
            auditEventPublisher.publish(
                AuditEvent(
                    type = "QR_CONSUMED",
                    userId = consumed.user.userId,
                    principal = consumed.user.username,
                    ip = clientIp(servletRequest),
                    userAgent = clientUserAgent(servletRequest),
                    detail = requestDetail(servletRequest, "sceneCode" to sceneCode)
                )
            )
            auditEventPublisher.publish(
                AuditEvent(
                    type = "LOGIN_SUCCESS",
                    userId = consumed.user.userId,
                    principal = consumed.user.username,
                    ip = clientIp(servletRequest),
                    userAgent = clientUserAgent(servletRequest),
                    detail = mapOf("loginType" to "QR")
                )
            )
            return ApiResponse.ok(
                consumed.scene.toResponse(
                    auth = buildAuthResponse(user, servletRequest)
                )
            )
        }

        val scene = qrLoginService().getScene(sceneCode) ?: throw IllegalArgumentException("auth.qr.scene.notFound")
        return ApiResponse.ok(scene.toResponse())
    }

    @PostMapping("/qr/scan")
    fun scanQrScene(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: QrScanRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<QrSceneResponse> {
        val principal = userId ?: throw AuthenticatedUserNotFoundException()
        val scene = qrLoginService().scanScene(request.sceneCode, principal)
        val user = enrichUser(principal)
        auditEventPublisher.publish(
            AuditEvent(
                type = "QR_SCANNED",
                userId = principal,
                principal = user.username,
                ip = clientIp(servletRequest),
                userAgent = clientUserAgent(servletRequest),
                detail = requestDetail(servletRequest, "sceneCode" to request.sceneCode)
            )
        )
        return ApiResponse.ok(scene.toResponse())
    }

    @PostMapping("/qr/confirm")
    fun confirmQrScene(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: QrConfirmRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<QrSceneResponse> {
        val principal = userId ?: throw AuthenticatedUserNotFoundException()
        val scene = qrLoginService().confirmScene(request.sceneCode, principal)
        val user = enrichUser(principal)
        auditEventPublisher.publish(
            AuditEvent(
                type = "QR_CONFIRMED",
                userId = principal,
                principal = user.username,
                ip = clientIp(servletRequest),
                userAgent = clientUserAgent(servletRequest),
                detail = requestDetail(servletRequest, "sceneCode" to request.sceneCode)
            )
        )
        return ApiResponse.ok(scene.toResponse())
    }

    @PostMapping("/qr/cancel")
    fun cancelQrScene(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: QrCancelRequest,
        servletRequest: HttpServletRequest
    ): ApiResponse<QrSceneResponse> {
        val scene = qrLoginService().cancelScene(request.sceneCode, userId)
        val username = userId?.let { enrichUser(it).username }
        auditEventPublisher.publish(
            AuditEvent(
                type = "QR_CANCELED",
                userId = userId,
                principal = username,
                ip = clientIp(servletRequest),
                userAgent = clientUserAgent(servletRequest),
                detail = requestDetail(servletRequest, "sceneCode" to request.sceneCode)
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
        val currentSessionId = currentAuthenticatedUser()?.attributes?.get("sessionId") as? String
        val currentUserId = (SecurityContextHolder.getContext().authentication?.principal as? Long)
        authorization
            ?.takeIf { it.startsWith("Bearer ") }
            ?.removePrefix("Bearer ")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.let(tokenService::invalidate)
        tokenService.invalidate(request.refreshToken)
        if (!currentSessionId.isNullOrBlank() && currentUserId != null) {
            sessionManagementServiceProvider.ifAvailable?.revokeSession(currentUserId, currentSessionId, "LOGOUT")
        }
        return ApiResponse.ok(true)
    }

    @GetMapping("/register/options")
    fun registrationOptions(): ApiResponse<RegistrationOptionsResponse> =
        ApiResponse.ok(
            RegistrationOptionsResponse(
                selfServiceEnabled = selfRegistrationEnabled,
                passwordMinLength = passwordMinLength
            )
        )

    @PostMapping("/register")
    fun register(@Valid @RequestBody request: RegisterRequest): ApiResponse<RegisterResponse> {
        require(selfRegistrationEnabled) { "auth.register.disabled" }
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

    /**
     * Register an account for external users (e.g. overseas students) who cannot
     * use WeChat. Creates a PENDING_EMAIL user and dispatches an activation email.
     * Does NOT require authentication. Rate-limit at the gateway/load-balancer level.
     */
    @PostMapping("/external-register")
    fun externalRegister(
        @Valid @RequestBody request: ExternalRegisterRequest
    ): ApiResponse<Map<String, Any>> {
        val evService = emailVerificationService()
        val mailer = mailSenderService()
        val result = userRegistrationService.register(
            UserRegistrationCommand(
                username = request.username,
                password = request.password,
                email = request.email,
                mobile = null,
                displayName = request.displayName,
                initialStatus = 3 // PENDING_EMAIL
            )
        )
        val token = evService.generate(result.userId, request.email, emailVerifyTokenTtlSeconds)
        val link = buildActivationLink(token)
        mailer.send(
            to = request.email,
            subject = emailActivationSubject,
            bodyHtml = buildActivationEmail(request.displayName ?: request.username, link)
        )
        return ApiResponse.ok(mapOf("userId" to result.userId, "message" to "Activation email sent"))
    }

    /**
     * Activate an account via the emailed token. Changes status PENDING_EMAIL →
     * PENDING_APPROVAL so an admin can then approve the account.
     */
    @GetMapping("/email-verify")
    fun emailVerify(@RequestParam("token") token: String): ApiResponse<Map<String, String>> {
        val evService = emailVerificationService()
        val claim = evService.consume(token.trim())
            ?: throw IllegalArgumentException("auth.email.verify.token.invalid")
        // Advance status: PENDING_EMAIL(3) → PENDING_APPROVAL(4)
        userRegistrationService.advanceUserStatus(claim.userId, fromStatus = 3, toStatus = 4)
        return ApiResponse.ok(mapOf("message" to "Email verified. Pending admin approval."))
    }

    /**
     * Resend the activation email for an account that is still in PENDING_EMAIL state.
     * Rate-limit at the gateway level; minimal server-side check only.
     */
    @PostMapping("/external-register/resend")
    fun resendActivation(
        @Valid @RequestBody request: ResendActivationRequest
    ): ApiResponse<Map<String, String>> {
        val evService = emailVerificationService()
        val mailer = mailSenderService()
        val principal = userLookupService.findByPrincipal(request.email)
            ?: return ApiResponse.ok(mapOf("message" to "If this email is registered, an activation link has been sent."))
        if (principal.principal.status.name != "PENDING_EMAIL") {
            return ApiResponse.ok(mapOf("message" to "If this email is registered, an activation link has been sent."))
        }
        val token = evService.generate(principal.principal.userId, request.email, emailVerifyTokenTtlSeconds)
        val link = buildActivationLink(token)
        mailer.send(
            to = request.email,
            subject = emailActivationSubject,
            bodyHtml = buildActivationEmail(
                principal.principal.displayName ?: principal.principal.username,
                link
            )
        )
        return ApiResponse.ok(mapOf("message" to "If this email is registered, an activation link has been sent."))
    }

    private fun emailVerificationService(): EmailVerificationService =
        emailVerificationService.ifAvailable
            ?: throw IllegalStateException("auth.email.verificationService.missing")

    private fun mailSenderService(): MailSenderService =
        mailSenderService.ifAvailable
            ?: throw IllegalStateException("auth.email.mailSender.missing")

    private fun buildActivationLink(token: String): String {
        val base = emailActivationBaseUrl.trimEnd('/')
        return if (base.isNotBlank()) "$base/auth/email-verify?token=$token"
        else "/auth/email-verify?token=$token"
    }

    private fun buildActivationEmail(name: String, link: String): String =
        """
        <html><body>
        <p>Hi $name,</p>
        <p>Click the link below to activate your account. The link expires in 24 hours.</p>
        <p><a href="$link">Activate My Account</a></p>
        <p>If you did not register, please ignore this email.</p>
        </body></html>
        """.trimIndent()

    @PostMapping("/password/change")
    fun changePassword(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: ChangePasswordRequest
    ): ApiResponse<Boolean> {
        val currentUserId = userId ?: throw AuthenticatedUserNotFoundException()
        val changedUserId = passwordManagementService.changePassword(
            ChangePasswordCommand(
                userId = currentUserId,
                oldPassword = request.oldPassword,
                newPassword = request.newPassword
            )
        )
        sessionManagementServiceProvider.ifAvailable?.revokeAllSessions(changedUserId, "PASSWORD_CHANGED")
        val user = enrichUser(changedUserId)
        auditEventPublisher.publish(
            AuditEvent(
                type = "PASSWORD_CHANGED",
                userId = changedUserId,
                principal = user.username
            )
        )
        return ApiResponse.ok(true)
    }

    @PostMapping("/password/reset")
    fun resetPassword(@Valid @RequestBody request: ResetPasswordRequest): ApiResponse<Boolean> {
        val resetUserId = passwordManagementService.resetPassword(
            ResetPasswordCommand(
                principal = request.principal,
                newPassword = request.newPassword
            )
        )
        sessionManagementServiceProvider.ifAvailable?.revokeAllSessions(resetUserId, "PASSWORD_RESET")
        auditEventPublisher.publish(
            AuditEvent(
                type = "PASSWORD_RESET",
                userId = resetUserId,
                principal = request.principal
            )
        )
        return ApiResponse.ok(true)
    }

    @GetMapping("/me")
    fun me(@AuthenticationPrincipal userId: Long?): ApiResponse<CurrentUserProfileResponse> {
        val currentUser = enrichUser(userId ?: throw AuthenticatedUserNotFoundException())
        val sessionId = currentAuthenticatedUser()?.attributes?.get("sessionId") as? String
        return ApiResponse.ok(
            CurrentUserProfileResponse(
                userId = currentUser.userId,
                username = currentUser.username,
                displayName = currentUser.displayName,
                sessionId = sessionId,
                deviceId = currentAuthenticatedUser()?.attributes?.get("deviceId") as? String,
                roles = currentUser.roles.sorted(),
                permissions = currentUser.permissions.sorted()
            )
        )
    }

    @GetMapping("/me/login-activities")
    fun myLoginActivities(@AuthenticationPrincipal userId: Long?): ApiResponse<List<LoginActivityResponse>> {
        val currentUser = enrichUser(userId ?: throw AuthenticatedUserNotFoundException())
        return ApiResponse.ok(
            auditQueryService.findMyLoginActivities(currentUser.userId, currentUser.username).map {
                LoginActivityResponse(
                    id = it.id,
                    userId = it.userId,
                    principal = it.principal,
                    loginType = it.loginType,
                    result = it.result,
                    ip = it.ip,
                    userAgent = it.userAgent,
                    location = it.location,
                    reason = it.reason,
                    createdAt = it.createdAt
                )
            }
        )
    }

    @GetMapping("/me/security-events")
    fun mySecurityEvents(@AuthenticationPrincipal userId: Long?): ApiResponse<List<SecurityEventResponse>> {
        val currentUser = enrichUser(userId ?: throw AuthenticatedUserNotFoundException())
        return ApiResponse.ok(
            auditQueryService.findMySecurityEvents(currentUser.userId).map {
                SecurityEventResponse(
                    id = it.id,
                    eventType = it.eventType,
                    userId = it.userId,
                    tenantId = it.tenantId,
                    detail = it.detail,
                    ip = it.ip,
                    createdAt = it.createdAt
                )
            }
        )
    }

    @GetMapping("/me/sessions")
    fun mySessions(@AuthenticationPrincipal userId: Long?): ApiResponse<List<SessionSummaryResponse>> {
        val currentUserId = userId ?: throw AuthenticatedUserNotFoundException()
        val currentSessionId = currentAuthenticatedUser()?.attributes?.get("sessionId") as? String
        val sessions = sessionManagementService().listSessions(currentUserId)
        return ApiResponse.ok(sessions.map { it.toResponse(currentSessionId) })
    }

    @PostMapping("/me/sessions/{sessionId}/revoke")
    fun revokeMySession(
        @AuthenticationPrincipal userId: Long?,
        @PathVariable sessionId: String
    ): ApiResponse<Boolean> =
        ApiResponse.ok(sessionManagementService().revokeSession(userId ?: throw AuthenticatedUserNotFoundException(), sessionId, "SELF_REVOKE"))

    @PostMapping("/me/sessions/revoke-others")
    fun revokeOtherMySessions(@AuthenticationPrincipal userId: Long?): ApiResponse<Map<String, Int>> {
        val currentUserId = userId ?: throw AuthenticatedUserNotFoundException()
        val currentSessionId = currentAuthenticatedUser()?.attributes?.get("sessionId") as? String
            ?: throw AuthenticatedUserNotFoundException()
        return ApiResponse.ok(
            mapOf("revokedCount" to sessionManagementService().revokeOtherSessions(currentUserId, currentSessionId, "REVOKE_OTHERS"))
        )
    }

    @GetMapping("/me/session-policy")
    fun mySessionPolicy(@AuthenticationPrincipal userId: Long?): ApiResponse<SessionPolicyResponse> =
        ApiResponse.ok(SessionPolicyResponse(sessionManagementService().getPolicy(userId ?: throw AuthenticatedUserNotFoundException()).name))

    @PostMapping("/me/session-policy")
    fun updateMySessionPolicy(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: UpdateSessionPolicyRequest
    ): ApiResponse<SessionPolicyResponse> {
        val policy = runCatching { SessionPolicyMode.valueOf(request.policy.trim().uppercase()) }
            .getOrElse { throw IllegalArgumentException("auth.session.policy.invalid") }
        val currentUserId = userId ?: throw AuthenticatedUserNotFoundException()
        val updated = sessionManagementService().updatePolicy(currentUserId, policy)
        val currentSessionId = currentAuthenticatedUser()?.attributes?.get("sessionId") as? String
        if (policy == SessionPolicyMode.SINGLE_DEVICE && !currentSessionId.isNullOrBlank()) {
            sessionManagementService().revokeOtherSessions(currentUserId, currentSessionId, "POLICY_SWITCH")
        }
        return ApiResponse.ok(SessionPolicyResponse(updated.name))
    }

    @GetMapping("/users/{userId}/sessions")
    fun userSessions(
        @AuthenticationPrincipal principalUserId: Long?,
        @PathVariable userId: Long
    ): ApiResponse<List<SessionSummaryResponse>> {
        val targetUser = ensureManageableUser(principalUserId, userId)
        val sessions = sessionManagementService().listSessions(targetUser.userId)
        return ApiResponse.ok(sessions.map { it.toResponse(currentSessionId = null) })
    }

    @PostMapping("/users/{userId}/sessions/{sessionId}/revoke")
    fun revokeUserSession(
        @AuthenticationPrincipal principalUserId: Long?,
        @PathVariable userId: Long,
        @PathVariable sessionId: String
    ): ApiResponse<Boolean> {
        val targetUser = ensureManageableUser(principalUserId, userId)
        return ApiResponse.ok(sessionManagementService().revokeSession(targetUser.userId, sessionId, "ADMIN_REVOKE"))
    }

    @PostMapping("/users/{userId}/sessions/revoke-all")
    fun revokeAllUserSessions(
        @AuthenticationPrincipal principalUserId: Long?,
        @PathVariable userId: Long
    ): ApiResponse<SessionRevokeResponse> {
        val targetUser = ensureManageableUser(principalUserId, userId)
        val revokedCount = sessionManagementService().revokeAllSessions(targetUser.userId, "ADMIN_REVOKE_ALL")
        return ApiResponse.ok(SessionRevokeResponse(revokedCount))
    }

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

    private fun buildAuthResponse(
        user: org.sainm.auth.core.domain.UserPrincipal,
        request: HttpServletRequest,
        clientId: String? = null,
        deviceId: String? = null,
        deviceType: String? = null,
        deviceName: String? = null
    ): AuthResponse {
        val tokenPair = tokenService.generate(
            user.copy(
                attributes = user.attributes + mapOf(
                    "clientId" to clientId?.trim()?.takeIf { it.isNotEmpty() },
                    "deviceId" to deviceId?.trim()?.takeIf { it.isNotEmpty() },
                    "deviceType" to deviceType?.trim()?.takeIf { it.isNotEmpty() },
                    "deviceName" to deviceName?.trim()?.takeIf { it.isNotEmpty() },
                    "userAgent" to request.getHeader(HttpHeaders.USER_AGENT)?.trim()?.takeIf { it.isNotEmpty() },
                    "ip" to request.remoteAddr?.trim()?.takeIf { it.isNotEmpty() }
                )
            )
        )
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

    private fun ssoStateStore(): SsoStateStore =
        ssoStateStoreProvider.ifAvailable ?: throw IllegalArgumentException("auth.sso.disabled")

    private fun ssoProvider(provider: String): SsoAuthProvider =
        ssoAuthProviders.orderedStream().filter { it.provider.uppercase() == provider }.findFirst().orElse(null)
            ?: throw IllegalArgumentException("auth.sso.provider.unsupported")

    private fun ssoRedirectUri(provider: String): String {
        require(ssoCallbackBaseUrl.isNotBlank()) { "auth.sso.callbackBaseUrl.missing" }
        return ssoCallbackBaseUrl.trimEnd('/') + "/auth/sso/" + provider.lowercase() + "/callback"
    }

    private fun sessionManagementService(): SessionManagementService =
        sessionManagementServiceProvider.ifAvailable ?: throw IllegalArgumentException("auth.session.invalid")

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

    private fun currentAuthenticatedUser(): org.sainm.auth.core.domain.UserPrincipal? =
        SecurityContextHolder.getContext().authentication?.credentials as? org.sainm.auth.core.domain.UserPrincipal

    private fun ensureManageableUser(
        principalUserId: Long?,
        targetUserId: Long
    ): org.sainm.auth.core.domain.UserPrincipal {
        val operator = enrichUser(principalUserId ?: throw AuthenticatedUserNotFoundException())
        val target = enrichUser(targetUserId)
        if ("SUPER_ADMIN" !in operator.roles && operator.tenantId != target.tenantId) {
            throw AccessDeniedException("auth.accessDenied")
        }
        return target
    }

    private fun socialAuthenticate(
        provider: String,
        authCode: String,
        request: HttpServletRequest
    ): org.sainm.auth.core.domain.UserPrincipal =
        runCatching {
            enrichUser(socialLoginService().authenticate(provider, authCode).userId)
        }.onSuccess { user ->
            auditEventPublisher.publish(
                AuditEvent(
                    type = "LOGIN_SUCCESS",
                    userId = user.userId,
                    principal = user.username,
                    ip = clientIp(request),
                    userAgent = clientUserAgent(request),
                    detail = mapOf("loginType" to provider)
                )
            )
        }.onFailure { error ->
            auditEventPublisher.publish(
                AuditEvent(
                    type = "LOGIN_FAIL",
                    principal = provider.lowercase(),
                    ip = clientIp(request),
                    userAgent = clientUserAgent(request),
                    detail = mapOf(
                        "loginType" to provider,
                        "reason" to (error.message ?: "social_auth_failed")
                    )
                )
            )
        }.getOrThrow()

    private fun requestDetail(
        request: HttpServletRequest,
        vararg pairs: Pair<String, Any?>
    ): Map<String, Any?> =
        linkedMapOf<String, Any?>().apply {
            putAll(pairs)
            clientUserAgent(request)?.let { put("userAgent", it) }
        }

    private fun clientIp(request: HttpServletRequest): String? =
        request.remoteAddr?.trim()?.takeIf { it.isNotEmpty() }

    private fun clientUserAgent(request: HttpServletRequest): String? =
        request.getHeader(HttpHeaders.USER_AGENT)?.trim()?.takeIf { it.isNotEmpty() }

    private fun org.sainm.auth.core.spi.UserSessionSummary.toResponse(currentSessionId: String?): SessionSummaryResponse =
        SessionSummaryResponse(
            sessionId = sessionId,
            userId = userId,
            username = username,
            tenantId = tenantId,
            clientId = clientId,
            deviceId = deviceId,
            deviceType = deviceType,
            deviceName = deviceName,
            userAgent = userAgent,
            ip = ip,
            status = status,
            current = sessionId == currentSessionId,
            lastSeenAt = lastSeenAt,
            accessExpireAt = accessExpireAt,
            refreshExpireAt = refreshExpireAt,
            createdAt = createdAt,
            updatedAt = updatedAt,
            revokedAt = revokedAt,
            revokeReason = revokeReason
        )

}
