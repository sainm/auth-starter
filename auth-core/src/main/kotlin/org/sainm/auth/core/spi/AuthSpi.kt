package org.sainm.auth.core.spi

import org.sainm.auth.core.domain.AuthResult
import org.sainm.auth.core.domain.LoginCommand
import org.sainm.auth.core.domain.TokenPair
import org.sainm.auth.core.domain.UserPrincipal

interface UserLookupService {
    fun findById(userId: Long): UserPrincipal?
    fun findByPrincipal(principal: String): UserCredentialView?
}

data class UserCredentialView(
    val principal: UserPrincipal,
    val passwordHash: String?
)

interface UserRegistrationService {
    fun register(command: UserRegistrationCommand): UserRegistrationResult
}

data class UserRegistrationCommand(
    val username: String,
    val password: String,
    val email: String?,
    val mobile: String?,
    val displayName: String?
)

data class UserRegistrationResult(
    val userId: Long,
    val username: String,
    val defaultRoles: Set<String>
)

interface PasswordManagementService {
    fun changePassword(command: ChangePasswordCommand)
    fun resetPassword(command: ResetPasswordCommand)
}

data class ChangePasswordCommand(
    val userId: Long,
    val oldPassword: String,
    val newPassword: String
)

data class ResetPasswordCommand(
    val principal: String,
    val newPassword: String
)

interface PermissionService {
    fun loadPermissions(userId: Long): Set<String>
    fun loadRoles(userId: Long): Set<String>
}

interface LoginAttemptService {
    fun resetAttempts(userId: Long)
    fun recordFailure(principal: String): LoginAttemptResult
}

data class LoginAttemptResult(
    val locked: Boolean,
    val remainingAttempts: Int?,
    val lockedUntilEpochSecond: Long?
)

interface AuditQueryService {
    fun findLoginLogs(page: Int, size: Int, principal: String? = null, result: String? = null): List<LoginLogRecord>
    fun findSecurityEvents(page: Int, size: Int, eventType: String? = null): List<SecurityEventRecord>
}

data class LoginLogRecord(
    val id: Long,
    val userId: Long?,
    val principal: String?,
    val loginType: String,
    val result: String,
    val reason: String?,
    val createdAt: String
)

data class SecurityEventRecord(
    val id: Long,
    val eventType: String,
    val userId: Long?,
    val tenantId: Long?,
    val detailJson: String?,
    val ip: String?,
    val createdAt: String
)

interface UserAdminService {
    fun listUsers(page: Int, size: Int, tenantId: Long? = null): List<UserSummary>
    fun listRoles(tenantId: Long? = null): List<RoleSummary>
    fun listPermissions(tenantId: Long? = null): List<PermissionSummary>
    fun assignRoles(command: RoleAssignmentCommand): Set<String>
}

data class UserSummary(
    val userId: Long,
    val username: String,
    val displayName: String?,
    val status: String,
    val groupId: Long?,
    val tenantId: Long?,
    val roles: Set<String>
)

data class RoleSummary(
    val roleId: Long,
    val roleCode: String,
    val roleName: String,
    val tenantId: Long?
)

data class PermissionSummary(
    val permissionId: Long,
    val permissionCode: String,
    val permissionName: String,
    val permissionType: String,
    val tenantId: Long?
)

data class RoleAssignmentCommand(
    val userId: Long,
    val roleCodes: Set<String>
)

interface OrganizationService {
    fun listGroups(tenantId: Long? = null): List<GroupSummary>
    fun createGroup(command: CreateGroupCommand): GroupSummary
    fun assignGroupRoles(command: GroupRoleAssignmentCommand): Set<String>
    fun listTenants(tenantId: Long? = null): List<TenantSummary>
    fun createTenant(command: CreateTenantCommand): TenantSummary
}

data class GroupSummary(
    val groupId: Long,
    val groupCode: String,
    val groupName: String,
    val tenantId: Long?,
    val parentId: Long? = null,
    val ancestors: String? = null,
    val roles: Set<String> = emptySet()
)

data class CreateGroupCommand(
    val groupCode: String,
    val groupName: String,
    val tenantId: Long?,
    val parentId: Long? = null
)

data class GroupRoleAssignmentCommand(
    val groupId: Long,
    val roleCodes: Set<String>
)

data class TenantSummary(
    val tenantId: Long,
    val tenantCode: String,
    val tenantName: String
)

data class CreateTenantCommand(
    val tenantCode: String,
    val tenantName: String
)

interface QrLoginService {
    fun createScene(): QrSceneSummary
    fun getScene(sceneCode: String): QrSceneSummary?
    fun scanScene(sceneCode: String, userId: Long): QrSceneSummary
    fun confirmScene(sceneCode: String, userId: Long): QrSceneSummary
    fun cancelScene(sceneCode: String, userId: Long? = null): QrSceneSummary
    fun consumeScene(sceneCode: String): QrLoginResult?
    fun cleanupExpiredScenes(retentionSeconds: Long = 86400): Int
}

data class QrSceneSummary(
    val sceneCode: String,
    val status: String,
    val expiresAtEpochSecond: Long,
    val scannedUserId: Long? = null,
    val approvedUserId: Long? = null
)

data class QrLoginResult(
    val scene: QrSceneSummary,
    val user: UserPrincipal
)

interface SocialLoginService {
    fun authenticate(provider: String, authCode: String): UserPrincipal
}

interface SocialAuthProvider {
    val provider: String
    fun resolve(authCode: String): SocialIdentity
}

interface SocialAccountService {
    fun findOrCreate(identity: SocialIdentity): UserPrincipal
}

data class SocialIdentity(
    val provider: String,
    val externalId: String,
    val displayName: String? = null,
    val email: String? = null
)

interface TokenBlacklistService {
    fun blacklist(jti: String, userId: Long, expireAtEpochSecond: Long)
    fun isBlacklisted(jti: String): Boolean
}

interface TokenService {
    fun generate(userPrincipal: UserPrincipal): TokenPair
    fun parse(accessToken: String): UserPrincipal
    fun refresh(refreshToken: String): TokenPair
    fun invalidate(accessToken: String)
}

interface AuthenticationHandler<T : LoginCommand> {
    fun supports(command: LoginCommand): Boolean
    fun authenticate(command: T): AuthResult
}

interface AuditEventPublisher {
    fun publish(event: AuditEvent)
}

data class AuditEvent(
    val type: String,
    val userId: Long? = null,
    val principal: String? = null,
    val detail: Map<String, Any?> = emptyMap()
)
