package org.sainm.auth.security.api

import jakarta.validation.constraints.NotBlank
import org.sainm.auth.core.domain.UserPrincipal

data class PasswordLoginRequest(
    @field:NotBlank
    val principal: String,
    @field:NotBlank
    val password: String
)

data class AuthResponse(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String,
    val expiresIn: Long,
    val user: UserPrincipal
)

data class RefreshTokenRequest(
    @field:NotBlank
    val refreshToken: String
)

data class LogoutRequest(
    @field:NotBlank
    val refreshToken: String
)

data class RegisterRequest(
    @field:NotBlank
    val username: String,
    @field:NotBlank
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
    @field:NotBlank
    val tenantCode: String,
    @field:NotBlank
    val tenantName: String
)

data class CreateGroupRequest(
    @field:NotBlank
    val groupCode: String,
    @field:NotBlank
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
    @field:NotBlank
    val sceneCode: String
)

data class QrConfirmRequest(
    @field:NotBlank
    val sceneCode: String
)

data class QrCancelRequest(
    @field:NotBlank
    val sceneCode: String
)

data class SocialLoginRequest(
    @field:NotBlank
    val authCode: String
)

data class ChangePasswordRequest(
    @field:NotBlank
    val oldPassword: String,
    @field:NotBlank
    val newPassword: String
)

data class ResetPasswordRequest(
    @field:NotBlank
    val principal: String,
    @field:NotBlank
    val newPassword: String
)
