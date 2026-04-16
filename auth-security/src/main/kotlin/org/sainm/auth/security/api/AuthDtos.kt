package org.sainm.auth.security.api

import jakarta.validation.constraints.NotBlank
import org.sainm.auth.core.domain.UserPrincipal

data class PasswordLoginRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val principal: String,
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val password: String,
    val clientId: String? = null,
    val deviceType: String? = null,
    val deviceName: String? = null
)

data class AuthResponse(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String,
    val expiresIn: Long,
    val user: UserPrincipal
)

data class CurrentUserProfileResponse(
    val userId: Long,
    val username: String,
    val displayName: String?,
    val sessionId: String?,
    val roles: List<String>,
    val permissions: List<String>
)

data class RefreshTokenRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val refreshToken: String
)

data class LogoutRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val refreshToken: String
)

data class RegisterRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val username: String,
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val password: String,
    val email: String? = null,
    val mobile: String? = null,
    val displayName: String? = null
)

data class RegisterResponse(
    val userId: Long,
    val username: String,
    val defaultRoles: Set<String>
)

data class RoleAssignRequest(
    val roleCodes: Set<String>
)

data class CreateTenantRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val tenantCode: String,
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val tenantName: String
)

data class CreateGroupRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val groupCode: String,
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val groupName: String,
    val tenantId: Long? = null,
    val parentId: Long? = null
)

data class GroupRoleAssignRequest(
    val roleCodes: Set<String>
)

data class QrSceneResponse(
    val sceneCode: String,
    val status: String,
    val expiresAt: Long,
    val scannedUserId: Long? = null,
    val approvedUserId: Long? = null,
    val auth: AuthResponse? = null
)

data class QrScanRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val sceneCode: String
)

data class QrConfirmRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val sceneCode: String
)

data class QrCancelRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val sceneCode: String
)

data class SocialLoginRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val authCode: String,
    val clientId: String? = null,
    val deviceType: String? = null,
    val deviceName: String? = null
)

data class ChangePasswordRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val oldPassword: String,
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val newPassword: String
)

data class ResetPasswordRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val principal: String,
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val newPassword: String
)

data class SessionSummaryResponse(
    val sessionId: String,
    val userId: Long,
    val username: String,
    val tenantId: Long?,
    val clientId: String?,
    val deviceType: String?,
    val deviceName: String?,
    val userAgent: String?,
    val ip: String?,
    val status: String,
    val current: Boolean,
    val lastSeenAt: String?,
    val accessExpireAt: String?,
    val refreshExpireAt: String?,
    val createdAt: String,
    val updatedAt: String,
    val revokedAt: String?,
    val revokeReason: String?
)

data class SessionPolicyResponse(
    val policy: String
)

data class UpdateSessionPolicyRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val policy: String
)

data class LoginActivityResponse(
    val id: Long,
    val userId: Long?,
    val principal: String?,
    val loginType: String,
    val result: String,
    val ip: String?,
    val userAgent: String?,
    val location: String?,
    val reason: String?,
    val createdAt: String
)

data class SecurityEventResponse(
    val id: Long,
    val eventType: String,
    val userId: Long?,
    val tenantId: Long?,
    val detail: Map<String, Any?>,
    val ip: String?,
    val createdAt: String
)
