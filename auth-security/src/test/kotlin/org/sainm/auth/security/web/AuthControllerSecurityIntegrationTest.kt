package org.sainm.auth.security.web

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.junit.jupiter.api.Test
import org.sainm.auth.core.domain.LoginCommand
import org.sainm.auth.core.domain.TokenPair
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.core.spi.AuditQueryService
import org.sainm.auth.core.spi.AuthenticationHandler
import org.sainm.auth.core.spi.DeviceGovernanceService
import org.sainm.auth.core.spi.DeviceRegistrationCommand
import org.sainm.auth.core.spi.GroupSummary
import org.sainm.auth.core.spi.LoginLogRecord
import org.sainm.auth.core.spi.MyLoginActivityRecord
import org.sainm.auth.core.spi.MySecurityEventRecord
import org.sainm.auth.core.spi.OrganizationService
import org.sainm.auth.core.spi.PasswordManagementService
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.PermissionSummary
import org.sainm.auth.core.spi.RoleAssignmentCommand
import org.sainm.auth.core.spi.RoleSummary
import org.sainm.auth.core.spi.SecurityEventRecord
import org.sainm.auth.core.spi.SessionManagementService
import org.sainm.auth.core.spi.SessionPolicyMode
import org.sainm.auth.core.spi.SessionTokenContext
import org.sainm.auth.core.spi.SocialLoginService
import org.sainm.auth.core.spi.UserSessionSummary
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserAdminService
import org.sainm.auth.core.spi.UserCredentialView
import org.sainm.auth.core.spi.UserDeviceDeactivationResult
import org.sainm.auth.core.spi.UserDeviceSummary
import org.sainm.auth.core.spi.UserLookupService
import org.sainm.auth.core.spi.UserRegistrationCommand
import org.sainm.auth.core.spi.UserRegistrationResult
import org.sainm.auth.core.spi.UserRegistrationService
import org.sainm.auth.core.spi.UserSummary
import org.sainm.auth.security.config.AuthSecurityConfiguration
import org.sainm.auth.security.handler.AuthenticationDispatcher
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import kotlin.test.assertEquals

@SpringBootTest(classes = [AuthControllerSecurityIntegrationTest.TestApplication::class])
@AutoConfigureMockMvc
class AuthControllerSecurityIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var userAdminService: RecordingUserAdminService

    @Autowired
    private lateinit var auditEventPublisher: RecordingAuditEventPublisher

    @Autowired
    private lateinit var sessionManagementService: RecordingSessionManagementService

    @Autowired
    private lateinit var deviceGovernanceService: RecordingDeviceGovernanceService

    @Test
    fun `users endpoint returns unauthorized without token`() {
        mockMvc.perform(get("/auth/users"))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.code").value("AUTH_401002"))
            .andExpect(jsonPath("$.message").value("Unauthorized"))
    }

    @Test
    fun `users endpoint returns forbidden when permission missing`() {
        mockMvc.perform(
            get("/auth/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer limited-token")
                .with(csrf())
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.code").value("AUTH_403001"))
            .andExpect(jsonPath("$.message").value("Access denied"))

        assertEquals("user2", auditEventPublisher.lastEvent?.principal)
        assertEquals(2L, auditEventPublisher.lastEvent?.userId)
        assertEquals("ACCESS_DENIED", auditEventPublisher.lastEvent?.type)
    }

    @Test
    fun `tenant scoped admin request ignores foreign tenant parameter`() {
        mockMvc.perform(
            get("/auth/users")
                .param("tenantId", "99")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .accept(MediaType.APPLICATION_JSON)
        ).andExpect(status().isOk)

        assertEquals(7L, userAdminService.lastTenantId)
    }

    @Test
    fun `super admin request may query explicit tenant`() {
        mockMvc.perform(
            get("/auth/users")
                .param("tenantId", "99")
                .header(HttpHeaders.AUTHORIZATION, "Bearer super-token")
                .accept(MediaType.APPLICATION_JSON)
        ).andExpect(status().isOk)

        assertEquals(99L, userAdminService.lastTenantId)
    }

    @Test
    fun `admin may list sessions for same tenant user`() {
        mockMvc.perform(
            get("/auth/users/5/sessions")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[0].userId").value(5))
            .andExpect(jsonPath("$.data[0].sessionId").value("managed-session"))
    }

    @Test
    fun `admin cannot list sessions for foreign tenant user`() {
        mockMvc.perform(
            get("/auth/users/6/sessions")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isForbidden)
    }

    @Test
    fun `super admin may revoke all sessions across tenant`() {
        mockMvc.perform(
            post("/auth/users/6/sessions/revoke-all")
                .header(HttpHeaders.AUTHORIZATION, "Bearer super-token")
                .with(csrf())
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.revokedCount").value(2))

        assertEquals(6L, sessionManagementService.lastRevokeAllUserId)
        assertEquals("ADMIN_REVOKE_ALL", sessionManagementService.lastRevokeAllReason)
    }

    @Test
    fun `admin may revoke single session for same tenant user`() {
        mockMvc.perform(
            post("/auth/users/5/sessions/managed-session/revoke")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .with(csrf())
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data").value(true))

        assertEquals(5L, sessionManagementService.lastRevokeUserId)
        assertEquals("managed-session", sessionManagementService.lastRevokeSessionId)
        assertEquals("ADMIN_REVOKE", sessionManagementService.lastRevokeReason)
    }

    @Test
    fun `admin may list devices for same tenant user`() {
        mockMvc.perform(
            get("/auth/users/5/devices")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[0].deviceId").value("web-device-tenant"))
            .andExpect(jsonPath("$.data[0].deviceTrustLevel").value("TRUSTED"))
    }

    @Test
    fun `admin may deactivate device for same tenant user`() {
        mockMvc.perform(
            post("/auth/users/5/devices/web-device-tenant/deactivate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .with(csrf())
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.device.deviceId").value("web-device-tenant"))
            .andExpect(jsonPath("$.data.revokedSessionCount").value(1))

        assertEquals(5L, deviceGovernanceService.lastDeactivateUserId)
        assertEquals("web-device-tenant", deviceGovernanceService.lastDeactivateDeviceId)
    }

    @Test
    fun `validation message uses english default`() {
        mockMvc.perform(
            post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.ACCEPT_LANGUAGE, "en-US")
                .content("""{"username":"","password":""}""")
                .with(csrf())
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.message").value("This field must not be blank"))
    }

    @Test
    fun `registration options expose self service flag`() {
        mockMvc.perform(
            get("/auth/register/options")
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.selfServiceEnabled").value(false))
            .andExpect(jsonPath("$.data.passwordMinLength").value(8))
    }

    @Test
    fun `register returns friendly message when self service is disabled`() {
        mockMvc.perform(
            post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.ACCEPT_LANGUAGE, "en-US")
                .content("""{"username":"new-user","password":"ChangeMe123"}""")
                .with(csrf())
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.message").value("Self-service registration is disabled"))
    }

    @Test
    fun `disabled qr login message uses english default`() {
        mockMvc.perform(
            post("/auth/qr/scene")
                .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-CN")
                .with(csrf())
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.message").value("QR login is disabled"))
    }

    @Test
    fun `change password revokes all sessions for current user`() {
        mockMvc.perform(
            post("/auth/password/change")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"oldPassword":"OldPass9","newPassword":"NewPass9"}""")
                .with(csrf())
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data").value(true))

        assertEquals(1L, sessionManagementService.lastRevokeAllUserId)
        assertEquals("PASSWORD_CHANGED", sessionManagementService.lastRevokeAllReason)
        assertEquals("PASSWORD_CHANGED", auditEventPublisher.lastEvent?.type)
        assertEquals(1L, auditEventPublisher.lastEvent?.userId)
    }

    @Test
    fun `reset password revokes all sessions for resolved user`() {
        mockMvc.perform(
            post("/auth/password/reset")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"principal":"user2","newPassword":"ResetPass9"}""")
                .with(csrf())
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data").value(true))

        assertEquals(2L, sessionManagementService.lastRevokeAllUserId)
        assertEquals("PASSWORD_RESET", sessionManagementService.lastRevokeAllReason)
        assertEquals("PASSWORD_RESET", auditEventPublisher.lastEvent?.type)
        assertEquals(2L, auditEventPublisher.lastEvent?.userId)
    }

    @Test
    fun `google social login publishes success audit with request metadata`() {
        mockMvc.perform(
            post("/auth/social/google")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.USER_AGENT, "JUnit-UA")
                .with { it.remoteAddr = "127.0.0.9"; it }
                .content("""{"authCode":"good-code","clientId":"web"}""")
                .with(csrf())
        )
            .andExpect(status().isOk)

        assertEquals("LOGIN_SUCCESS", auditEventPublisher.lastEvent?.type)
        assertEquals(4L, auditEventPublisher.lastEvent?.userId)
        assertEquals("social4", auditEventPublisher.lastEvent?.principal)
        assertEquals("127.0.0.9", auditEventPublisher.lastEvent?.ip)
        assertEquals("JUnit-UA", auditEventPublisher.lastEvent?.userAgent)
        assertEquals("GOOGLE", auditEventPublisher.lastEvent?.detail?.get("loginType"))
    }

    @Test
    fun `google social login failure publishes fail audit with request metadata`() {
        mockMvc.perform(
            post("/auth/social/google")
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.USER_AGENT, "JUnit-UA")
                .with { it.remoteAddr = "127.0.0.10"; it }
                .content("""{"authCode":"bad-code"}""")
                .with(csrf())
        )
            .andExpect(status().isBadRequest)

        assertEquals("LOGIN_FAIL", auditEventPublisher.lastEvent?.type)
        assertEquals("google", auditEventPublisher.lastEvent?.principal)
        assertEquals("127.0.0.10", auditEventPublisher.lastEvent?.ip)
        assertEquals("JUnit-UA", auditEventPublisher.lastEvent?.userAgent)
        assertEquals("GOOGLE", auditEventPublisher.lastEvent?.detail?.get("loginType"))
    }

    @SpringBootApplication
    @Import(AuthSecurityConfiguration::class, AuthController::class, DeviceGovernanceController::class, AuthExceptionHandler::class)
    class TestApplication {

        @Bean
        fun objectMapper(): ObjectMapper = ObjectMapper().registerKotlinModule()

        @Bean
        fun tokenService(): TokenService = object : TokenService {
            override fun generate(userPrincipal: UserPrincipal): TokenPair = TokenPair("access", "refresh", "Bearer", 1800)

            override fun parse(accessToken: String): UserPrincipal =
                when (accessToken) {
                    "admin-token" -> principal(1, 7, setOf("ADMIN"), setOf("api:GET:/auth/users"))
                    "limited-token" -> principal(2, 7, setOf("ADMIN"), emptySet())
                    "super-token" -> principal(3, 1, setOf("SUPER_ADMIN"), setOf("api:GET:/auth/users"))
                    else -> throw IllegalArgumentException("bad token")
                }

            override fun refresh(refreshToken: String): TokenPair = TokenPair("access", "refresh", "Bearer", 1800)

            override fun invalidate(accessToken: String) = Unit
        }

        @Bean
        fun authenticationDispatcher(): AuthenticationDispatcher =
            AuthenticationDispatcher(emptyList<AuthenticationHandler<out LoginCommand>>())

        @Bean
        fun userLookupService(): UserLookupService = object : UserLookupService {
            override fun findById(userId: Long): UserPrincipal? =
                when (userId) {
                    1L -> principal(1, 7, setOf("ADMIN"), setOf("api:GET:/auth/users"))
                    2L -> principal(2, 7, setOf("ADMIN"), emptySet())
                    3L -> principal(3, 1, setOf("SUPER_ADMIN"), setOf("api:GET:/auth/users"))
                    4L -> UserPrincipal(
                        userId = 4L,
                        username = "social4",
                        displayName = "Social 4",
                        status = UserStatus.ENABLED,
                        groupId = 1,
                        tenantId = 7L
                    )
                    5L -> UserPrincipal(
                        userId = 5L,
                        username = "tenant-user",
                        displayName = "Tenant User",
                        status = UserStatus.ENABLED,
                        groupId = 1,
                        tenantId = 7L
                    )
                    6L -> UserPrincipal(
                        userId = 6L,
                        username = "foreign-user",
                        displayName = "Foreign User",
                        status = UserStatus.ENABLED,
                        groupId = 1,
                        tenantId = 99L
                    )
                    else -> null
                }

            override fun findByPrincipal(principal: String): UserCredentialView? = null
        }

        @Bean
        fun permissionService(): PermissionService = object : PermissionService {
            override fun loadPermissions(userId: Long): Set<String> =
                userLookupService().findById(userId)?.permissions.orEmpty()

            override fun loadRoles(userId: Long): Set<String> =
                userLookupService().findById(userId)?.roles.orEmpty()
        }

        @Bean
        fun userRegistrationService(): UserRegistrationService = object : UserRegistrationService {
            override fun register(command: UserRegistrationCommand): UserRegistrationResult =
                UserRegistrationResult(99, command.username, setOf("USER"))
        }

        @Bean
        fun passwordManagementService(): PasswordManagementService = object : PasswordManagementService {
            override fun changePassword(command: org.sainm.auth.core.spi.ChangePasswordCommand): Long = command.userId
            override fun resetPassword(command: org.sainm.auth.core.spi.ResetPasswordCommand): Long =
                when (command.principal) {
                    "user2" -> 2L
                    else -> 99L
                }
        }

        @Bean
        fun auditEventPublisher(): RecordingAuditEventPublisher = RecordingAuditEventPublisher()

        @Bean
        fun auditQueryService(): AuditQueryService = object : AuditQueryService {
            override fun findLoginLogs(page: Int, size: Int, principal: String?, result: String?): List<LoginLogRecord> = emptyList()
            override fun findSecurityEvents(page: Int, size: Int, eventType: String?): List<SecurityEventRecord> = emptyList()
            override fun findMyLoginActivities(userId: Long, principal: String, limit: Int): List<MyLoginActivityRecord> = emptyList()
            override fun findMySecurityEvents(userId: Long, limit: Int): List<MySecurityEventRecord> = emptyList()
        }

        @Bean
        fun socialLoginService(): SocialLoginService = object : SocialLoginService {
            override fun authenticate(provider: String, authCode: String): UserPrincipal =
                when (authCode) {
                    "good-code" -> UserPrincipal(
                        userId = 4L,
                        username = "social4",
                        displayName = "Social 4",
                        status = UserStatus.ENABLED,
                        groupId = 1L,
                        tenantId = 7L
                    )
                    else -> throw IllegalArgumentException("auth.social.code.invalid")
                }
        }

        @Bean
        @Primary
        fun userAdminService(): RecordingUserAdminService = RecordingUserAdminService()

        @Bean
        @Primary
        fun sessionManagementService(): RecordingSessionManagementService = RecordingSessionManagementService()

        @Bean
        @Primary
        fun deviceGovernanceService(): RecordingDeviceGovernanceService = RecordingDeviceGovernanceService()

        @Bean
        fun organizationService(): OrganizationService = object : OrganizationService {
            override fun listGroups(tenantId: Long?): List<GroupSummary> = emptyList()
            override fun createGroup(command: org.sainm.auth.core.spi.CreateGroupCommand): GroupSummary =
                GroupSummary(1, command.groupCode, command.groupName, command.tenantId, command.parentId, null)

            override fun assignGroupRoles(command: org.sainm.auth.core.spi.GroupRoleAssignmentCommand): Set<String> = command.roleCodes
            override fun listTenants(tenantId: Long?): List<org.sainm.auth.core.spi.TenantSummary> = emptyList()
            override fun createTenant(command: org.sainm.auth.core.spi.CreateTenantCommand): org.sainm.auth.core.spi.TenantSummary =
                org.sainm.auth.core.spi.TenantSummary(1, command.tenantCode, command.tenantName)
        }
    }

    class RecordingUserAdminService : UserAdminService {
        var lastTenantId: Long? = null

        override fun listUsers(page: Int, size: Int, tenantId: Long?): List<UserSummary> {
            lastTenantId = tenantId
            return listOf(UserSummary(1, "admin", "Admin", "ENABLED", 1, tenantId, setOf("ADMIN")))
        }

        override fun listRoles(tenantId: Long?): List<RoleSummary> = emptyList()

        override fun listPermissions(tenantId: Long?): List<PermissionSummary> = emptyList()

        override fun assignRoles(command: RoleAssignmentCommand): Set<String> = command.roleCodes
    }

    class RecordingAuditEventPublisher : AuditEventPublisher {
        var lastEvent: AuditEvent? = null

        override fun publish(event: AuditEvent) {
            lastEvent = event
        }
    }

    class RecordingDeviceGovernanceService : DeviceGovernanceService {
        var lastDeactivateUserId: Long? = null
        var lastDeactivateDeviceId: String? = null

        override fun listMyDevices(userId: Long): List<UserDeviceSummary> = listUserDevices(userId)

        override fun registerMyDevice(command: DeviceRegistrationCommand): UserDeviceSummary =
            sampleDevice(command.userId, command.deviceId ?: "registered-device")

        override fun deactivateMyDevice(userId: Long, deviceId: String): UserDeviceSummary =
            sampleDevice(userId, deviceId, activeFlag = false, trust = "STALE", riskSignals = listOf("DEVICE_INACTIVE"))

        override fun listUserDevices(userId: Long): List<UserDeviceSummary> =
            when (userId) {
                5L -> listOf(sampleDevice(userId, "web-device-tenant"))
                6L -> listOf(sampleDevice(userId, "web-device-foreign", tenantSessionId = "foreign-session"))
                else -> emptyList()
            }

        override fun deactivateUserDevice(userId: Long, deviceId: String): UserDeviceDeactivationResult {
            lastDeactivateUserId = userId
            lastDeactivateDeviceId = deviceId
            return UserDeviceDeactivationResult(
                device = sampleDevice(
                    userId = userId,
                    deviceId = deviceId,
                    activeFlag = false,
                    trust = "STALE",
                    riskSignals = listOf("DEVICE_INACTIVE")
                ),
                revokedSessionCount = 1
            )
        }

        private fun sampleDevice(
            userId: Long,
            deviceId: String,
            activeFlag: Boolean = true,
            trust: String = "TRUSTED",
            riskSignals: List<String> = emptyList(),
            tenantSessionId: String = "managed-session"
        ): UserDeviceSummary =
            UserDeviceSummary(
                id = if (userId == 6L) 61L else 51L,
                deviceType = "WEB",
                deviceId = deviceId,
                pushTokenMasked = null,
                appVersion = "1.0.0",
                activeFlag = activeFlag,
                authSessionId = tenantSessionId,
                authSessionStatus = if (activeFlag) "ACTIVE" else "REVOKED",
                authSessionLastSeenAt = "2026-04-17T00:00:00Z",
                deviceTrustLevel = trust,
                riskSignals = riskSignals,
                riskLevel = if (riskSignals.isEmpty()) "LOW" else "HIGH",
                autoDisposition = if (riskSignals.isEmpty()) "NONE" else "REVIEW_ONLY",
                autoDispositionReason = riskSignals.firstOrNull(),
                lastActiveAt = "2026-04-17T00:00:00Z",
                createdAt = "2026-04-17T00:00:00Z",
                updatedAt = "2026-04-17T00:00:00Z"
            )
    }

    class RecordingSessionManagementService : SessionManagementService {
        var lastRevokeAllUserId: Long? = null
        var lastRevokeAllReason: String? = null
        var lastRevokeUserId: Long? = null
        var lastRevokeSessionId: String? = null
        var lastRevokeReason: String? = null

        override fun openSession(command: org.sainm.auth.core.spi.SessionOpenCommand): SessionTokenContext =
            SessionTokenContext("session-1", SessionPolicyMode.MULTI_DEVICE)

        override fun touchSession(sessionId: String, userId: Long, accessExpireAtEpochSecond: Long, refreshExpireAtEpochSecond: Long): Boolean = true

        override fun recordSessionActivity(sessionId: String, userId: Long): Boolean = true

        override fun isSessionActive(sessionId: String, userId: Long): Boolean = true

        override fun listSessions(userId: Long, limit: Int): List<UserSessionSummary> =
            when (userId) {
                5L -> listOf(
                    UserSessionSummary(
                        sessionId = "managed-session",
                        userId = 5L,
                        username = "tenant-user",
                        tenantId = 7L,
                        clientId = "admin-web",
                        deviceId = "web-device-tenant",
                        deviceType = "WEB",
                        deviceName = "Chrome",
                        userAgent = "JUnit",
                        ip = "127.0.0.1",
                        status = "ACTIVE",
                        lastSeenAt = "2026-04-17T00:00:00Z",
                        accessExpireAt = "2026-04-17T01:00:00Z",
                        refreshExpireAt = "2026-04-24T00:00:00Z",
                        createdAt = "2026-04-17T00:00:00Z",
                        updatedAt = "2026-04-17T00:00:00Z",
                        revokedAt = null,
                        revokeReason = null
                    )
                )
                6L -> listOf(
                    UserSessionSummary(
                        sessionId = "foreign-session",
                        userId = 6L,
                        username = "foreign-user",
                        tenantId = 99L,
                        clientId = "admin-web",
                        deviceId = "web-device-foreign",
                        deviceType = "WEB",
                        deviceName = "Edge",
                        userAgent = "JUnit",
                        ip = "127.0.0.2",
                        status = "ACTIVE",
                        lastSeenAt = "2026-04-17T00:00:00Z",
                        accessExpireAt = "2026-04-17T01:00:00Z",
                        refreshExpireAt = "2026-04-24T00:00:00Z",
                        createdAt = "2026-04-17T00:00:00Z",
                        updatedAt = "2026-04-17T00:00:00Z",
                        revokedAt = null,
                        revokeReason = null
                    )
                )
                else -> emptyList()
            }

        override fun findLatestSessionByDevice(userId: Long, deviceId: String): UserSessionSummary? =
            listSessions(userId).firstOrNull { it.deviceId == deviceId }

        override fun revokeSession(userId: Long, sessionId: String, reason: String?): Boolean {
            lastRevokeUserId = userId
            lastRevokeSessionId = sessionId
            lastRevokeReason = reason
            return true
        }

        override fun revokeSessionsByDevice(userId: Long, deviceId: String, reason: String?): Int = 0

        override fun revokeOtherSessions(userId: Long, currentSessionId: String, reason: String?): Int = 0

        override fun revokeAllSessions(userId: Long, reason: String?): Int {
            lastRevokeAllUserId = userId
            lastRevokeAllReason = reason
            return if (userId == 6L) 2 else 1
        }

        override fun getPolicy(userId: Long): SessionPolicyMode = SessionPolicyMode.MULTI_DEVICE

        override fun updatePolicy(userId: Long, policy: SessionPolicyMode): SessionPolicyMode = policy
    }
}

private fun principal(
    userId: Long,
    tenantId: Long?,
    roles: Set<String>,
    permissions: Set<String>
): UserPrincipal =
    UserPrincipal(
        userId = userId,
        username = "user$userId",
        displayName = "User $userId",
        status = UserStatus.ENABLED,
        groupId = 1,
        tenantId = tenantId,
        roles = roles,
        permissions = permissions
    )
