package org.sainm.auth.security.token

import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.exception.InvalidTokenException
import org.sainm.auth.core.spi.TokenBlacklistService
import org.sainm.auth.core.spi.UserCredentialView
import org.sainm.auth.core.spi.UserLookupService
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JwtTokenServiceTest {

    private val principal = UserPrincipal(
        userId = 7L,
        username = "tester",
        displayName = "Tester",
        status = UserStatus.ENABLED,
        groupId = 2L,
        tenantId = 3L,
        roles = setOf("ADMIN"),
        permissions = setOf("api:GET:/auth/me"),
        attributes = mapOf("passwordVersion" to 1)
    )

    @Test
    fun `generate and parse preserves principal claims`() {
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            )
        )

        val tokenPair = service.generate(principal)
        val parsed = service.parse(tokenPair.accessToken)

        assertEquals(principal.userId, parsed.userId)
        assertEquals(principal.username, parsed.username)
        assertEquals(principal.roles, parsed.roles)
        assertEquals(principal.permissions, parsed.permissions)
        assertEquals(principal.groupId, parsed.groupId)
        assertEquals(principal.tenantId, parsed.tenantId)
    }

    @Test
    fun `refresh invalidates old refresh token`() {
        val blacklist = InMemoryTokenBlacklistService()
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            tokenBlacklistService = blacklist
        )

        val tokenPair = service.generate(principal)
        val refreshed = service.refresh(tokenPair.refreshToken)

        assertTrue(refreshed.accessToken.isNotBlank())
        assertFailsWith<InvalidTokenException> {
            service.refresh(tokenPair.refreshToken)
        }
    }

    @Test
    fun `invalidate blacklists access token`() {
        val blacklist = InMemoryTokenBlacklistService()
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            tokenBlacklistService = blacklist
        )

        val tokenPair = service.generate(principal)
        service.invalidate(tokenPair.accessToken)

        assertFailsWith<InvalidTokenException> {
            service.parse(tokenPair.accessToken)
        }
    }

    @Test
    fun `password version mismatch invalidates old token`() {
        val service = JwtTokenService(
            properties = JwtTokenProperties(
                secret = "change-me-change-me-change-me-change-me",
                issuer = "unit-test",
                accessTokenExpireMinutes = 30,
                refreshTokenExpireDays = 7
            ),
            userLookupService = object : UserLookupService {
                override fun findById(userId: Long): UserPrincipal =
                    principal.copy(attributes = mapOf("passwordVersion" to 2))

                override fun findByPrincipal(principal: String): UserCredentialView? = null
            }
        )

        val tokenPair = service.generate(principal)

        assertFailsWith<InvalidTokenException> {
            service.parse(tokenPair.accessToken)
        }
    }
}

private class InMemoryTokenBlacklistService : TokenBlacklistService {
    private val blacklisted = mutableSetOf<String>()

    override fun blacklist(jti: String, userId: Long, expireAtEpochSecond: Long) {
        blacklisted += jti
    }

    override fun isBlacklisted(jti: String): Boolean = jti in blacklisted
}
