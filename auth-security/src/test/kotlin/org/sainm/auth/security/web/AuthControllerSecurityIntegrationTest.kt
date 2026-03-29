package org.sainm.auth.security.web

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.sainm.auth.core.domain.LoginCommand
import org.sainm.auth.core.domain.TokenPair
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.core.spi.AuditQueryService
import org.sainm.auth.core.spi.AuthenticationHandler
import org.sainm.auth.core.spi.GroupSummary
import org.sainm.auth.core.spi.LoginLogRecord
import org.sainm.auth.core.spi.OrganizationService
import org.sainm.auth.core.spi.PasswordManagementService
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.PermissionSummary
import org.sainm.auth.core.spi.RoleAssignmentCommand
import org.sainm.auth.core.spi.RoleSummary
import org.sainm.auth.core.spi.SecurityEventRecord
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserAdminService
import org.sainm.auth.core.spi.UserCredentialView
import org.sainm.auth.core.spi.UserLookupService
import org.sainm.auth.core.spi.UserRegistrationCommand
import org.sainm.auth.core.spi.UserRegistrationResult
import org.sainm.auth.core.spi.UserRegistrationService
import org.sainm.auth.core.spi.UserSummary
import org.sainm.auth.security.config.AuthSecurityConfiguration
import org.sainm.auth.security.handler.AuthenticationDispatcher
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Primary
import kotlin.test.assertEquals

@SpringBootTest(classes = [AuthControllerSecurityIntegrationTest.TestApplication::class])
@AutoConfigureMockMvc
class AuthControllerSecurityIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var userAdminService: RecordingUserAdminService

    @Test
    fun `users endpoint returns unauthorized without token`() {
        mockMvc.perform(get("/auth/users"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `users endpoint returns forbidden when permission missing`() {
        mockMvc.perform(
            get("/auth/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer limited-token")
                .with(csrf())
        ).andExpect(status().isForbidden)
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

    @SpringBootApplication
    @Import(AuthSecurityConfiguration::class, AuthController::class, AuthExceptionHandler::class)
    class TestApplication {

        @Bean
        fun objectMapper(): ObjectMapper = ObjectMapper()

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
            override fun changePassword(command: org.sainm.auth.core.spi.ChangePasswordCommand) = Unit
            override fun resetPassword(command: org.sainm.auth.core.spi.ResetPasswordCommand) = Unit
        }

        @Bean
        fun auditEventPublisher(): AuditEventPublisher = object : AuditEventPublisher {
            override fun publish(event: AuditEvent) = Unit
        }

        @Bean
        fun auditQueryService(): AuditQueryService = object : AuditQueryService {
            override fun findLoginLogs(page: Int, size: Int, principal: String?, result: String?): List<LoginLogRecord> = emptyList()
            override fun findSecurityEvents(page: Int, size: Int, eventType: String?): List<SecurityEventRecord> = emptyList()
        }

        @Bean
        @Primary
        fun userAdminService(): RecordingUserAdminService = RecordingUserAdminService()

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
