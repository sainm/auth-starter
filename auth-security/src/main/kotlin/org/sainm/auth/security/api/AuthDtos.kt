package org.sainm.auth.security.api

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.sainm.auth.core.domain.UserPrincipal

data class PasswordLoginRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val principal: String,
    @field:NotBlank(message = "{auth.validation.notBlank}")
    val password: String,
    @field:Size(max = 64, message = "{auth.validation.notBlank}")
    val clientId: String? = null,
    @field:Size(max = 128, message = "{auth.validation.notBlank}")
    val deviceId: String? = null,
    @field:Size(max = 32, message = "{auth.validation.notBlank}")
    val deviceType: String? = null,
    @field:Size(max = 128, message = "{auth.validation.notBlank}")
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
    val deviceId: String?,
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

data class RegistrationOptionsResponse(
    val selfServiceEnabled: Boolean,
    val passwordMinLength: Int
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
    @field:Size(max = 64, message = "{auth.validation.notBlank}")
    val clientId: String? = null,
    @field:Size(max = 128, message = "{auth.validation.notBlank}")
    val deviceId: String? = null,
    @field:Size(max = 32, message = "{auth.validation.notBlank}")
    val deviceType: String? = null,
    @field:Size(max = 128, message = "{auth.validation.notBlank}")
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
    val deviceId: String?,
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

data class SessionRevokeResponse(
    val revokedCount: Int
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

data class DeviceRegistrationRequest(
    @field:NotBlank(message = "{auth.validation.notBlank}")
    @field:Size(max = 32, message = "{auth.validation.notBlank}")
    val deviceType: String,
    @field:Size(max = 128, message = "{auth.validation.notBlank}")
    val deviceId: String? = null,
    @field:Size(max = 512, message = "{auth.validation.notBlank}")
    val pushToken: String? = null,
    @field:Size(max = 64, message = "{auth.validation.notBlank}")
    val appVersion: String? = null
)

data class UserDeviceSummaryResponse(
    val id: Long,
    val deviceType: String,
    val deviceId: String,
    val pushTokenMasked: String?,
    val appVersion: String?,
    val activeFlag: Boolean,
    val authSessionId: String?,
    val authSessionStatus: String?,
    val authSessionLastSeenAt: String?,
    val deviceTrustLevel: String,
    val riskSignals: List<String>,
    val riskLevel: String,
    val autoDisposition: String,
    val autoDispositionReason: String?,
    val lastActiveAt: String?,
    val createdAt: String,
    val updatedAt: String
)

data class UserDeviceDeactivationResponse(
    val device: UserDeviceSummaryResponse,
    val revokedSessionCount: Int
)
