package org.sainm.auth.security.web

import jakarta.validation.Valid
import org.sainm.auth.core.exception.AuthenticatedUserNotFoundException
import org.sainm.auth.core.spi.DeviceGovernanceService
import org.sainm.auth.core.spi.DeviceRegistrationCommand
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.UserLookupService
import org.sainm.auth.security.api.ApiResponse
import org.sainm.auth.security.api.DeviceRegistrationRequest
import org.sainm.auth.security.api.UserDeviceDeactivationResponse
import org.sainm.auth.security.api.UserDeviceSummaryResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class DeviceGovernanceController(
    private val userLookupService: UserLookupService,
    private val permissionService: PermissionService,
    private val deviceGovernanceService: DeviceGovernanceService
) {

    @GetMapping("/me/devices")
    fun myDevices(@AuthenticationPrincipal userId: Long?): ApiResponse<List<UserDeviceSummaryResponse>> =
        ApiResponse.ok(
            deviceGovernanceService.listMyDevices(userId ?: throw AuthenticatedUserNotFoundException())
                .map { it.toResponse() }
        )

    @PostMapping("/me/devices")
    fun registerMyDevice(
        @AuthenticationPrincipal userId: Long?,
        @Valid @RequestBody request: DeviceRegistrationRequest
    ): ApiResponse<UserDeviceSummaryResponse> =
        ApiResponse.ok(
            deviceGovernanceService.registerMyDevice(
                DeviceRegistrationCommand(
                    userId = userId ?: throw AuthenticatedUserNotFoundException(),
                    deviceType = request.deviceType,
                    deviceId = request.deviceId,
                    pushToken = request.pushToken,
                    appVersion = request.appVersion
                )
            ).toResponse()
        )

    @PostMapping("/me/devices/{deviceId}/deactivate")
    fun deactivateMyDevice(
        @AuthenticationPrincipal userId: Long?,
        @PathVariable deviceId: String
    ): ApiResponse<UserDeviceSummaryResponse> =
        ApiResponse.ok(
            deviceGovernanceService.deactivateMyDevice(
                userId = userId ?: throw AuthenticatedUserNotFoundException(),
                deviceId = deviceId
            ).toResponse()
        )

    @GetMapping("/users/{userId}/devices")
    fun userDevices(
        @AuthenticationPrincipal principalUserId: Long?,
        @PathVariable userId: Long
    ): ApiResponse<List<UserDeviceSummaryResponse>> {
        val targetUser = ensureManageableUser(principalUserId, userId)
        return ApiResponse.ok(deviceGovernanceService.listUserDevices(targetUser.userId).map { it.toResponse() })
    }

    @PostMapping("/users/{userId}/devices/{deviceId}/deactivate")
    fun deactivateUserDevice(
        @AuthenticationPrincipal principalUserId: Long?,
        @PathVariable userId: Long,
        @PathVariable deviceId: String
    ): ApiResponse<UserDeviceDeactivationResponse> {
        val targetUser = ensureManageableUser(principalUserId, userId)
        val result = deviceGovernanceService.deactivateUserDevice(targetUser.userId, deviceId)
        return ApiResponse.ok(
            UserDeviceDeactivationResponse(
                device = result.device.toResponse(),
                revokedSessionCount = result.revokedSessionCount
            )
        )
    }

    private fun enrichUser(userId: Long) =
        userLookupService.findById(userId)
            ?.copy(
                roles = permissionService.loadRoles(userId),
                permissions = permissionService.loadPermissions(userId)
            )
            ?: throw AuthenticatedUserNotFoundException()

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

    private fun org.sainm.auth.core.spi.UserDeviceSummary.toResponse(): UserDeviceSummaryResponse =
        UserDeviceSummaryResponse(
            id = id,
            deviceType = deviceType,
            deviceId = deviceId,
            pushTokenMasked = pushTokenMasked,
            appVersion = appVersion,
            activeFlag = activeFlag,
            authSessionId = authSessionId,
            authSessionStatus = authSessionStatus,
            authSessionLastSeenAt = authSessionLastSeenAt,
            deviceTrustLevel = deviceTrustLevel,
            riskSignals = riskSignals,
            riskLevel = riskLevel,
            autoDisposition = autoDisposition,
            autoDispositionReason = autoDispositionReason,
            lastActiveAt = lastActiveAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
}
