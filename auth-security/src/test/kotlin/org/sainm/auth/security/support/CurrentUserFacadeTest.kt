package org.sainm.auth.security.support

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.exception.AuthenticatedUserNotFoundException
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.UserLookupService
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder

@ExtendWith(MockitoExtension::class)
class CurrentUserFacadeTest {

    @Mock private lateinit var userLookupService: UserLookupService
    @Mock private lateinit var permissionService: PermissionService

    @AfterEach
    fun tearDown() {
        SecurityContextHolder.clearContext()
    }

    @Test
    fun `requireCurrentUser enriches principal with roles and permissions`() {
        val facade = CurrentUserFacade(userLookupService, permissionService)
        SecurityContextHolder.getContext().authentication =
            UsernamePasswordAuthenticationToken(9L, "token")
        `when`(userLookupService.findById(9L)).thenReturn(
            UserPrincipal(
                userId = 9L,
                username = "demo",
                displayName = "Demo",
                status = UserStatus.ENABLED,
                groupId = 1L,
                tenantId = 2L
            )
        )
        `when`(permissionService.loadRoles(9L)).thenReturn(setOf("SYS_ADMIN"))
        `when`(permissionService.loadPermissions(9L)).thenReturn(setOf("api:GET:/demo"))

        val currentUser = facade.requireCurrentUser()

        assertEquals(9L, currentUser.userId)
        assertEquals(setOf("SYS_ADMIN"), currentUser.roles)
        assertEquals(setOf("api:GET:/demo"), currentUser.permissions)
    }

    @Test
    fun `requireCurrentUserId throws when authentication principal is absent`() {
        val facade = CurrentUserFacade(userLookupService, permissionService)

        assertThrows(AuthenticatedUserNotFoundException::class.java) {
            facade.requireCurrentUserId()
        }
    }
}
