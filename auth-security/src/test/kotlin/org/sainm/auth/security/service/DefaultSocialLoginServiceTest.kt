package org.sainm.auth.security.service

import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.spi.SocialAccountService
import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialIdentity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DefaultSocialLoginServiceTest {

    @Test
    fun `uses matching provider and delegates to account service`() {
        val service = DefaultSocialLoginService(
            providers = listOf(
                object : SocialAuthProvider {
                    override val provider: String = "GOOGLE"
                    override fun resolve(authCode: String): SocialIdentity =
                        SocialIdentity(provider = provider, externalId = "google:$authCode")
                }
            ),
            socialAccountService = object : SocialAccountService {
                override fun findOrCreate(identity: SocialIdentity): UserPrincipal =
                    UserPrincipal(
                        userId = 11L,
                        username = identity.externalId,
                        displayName = null,
                        status = UserStatus.ENABLED,
                        groupId = null,
                        tenantId = null
                    )
            }
        )

        val user = service.authenticate("google", "demo-code")

        assertEquals("google:demo-code", user.username)
    }

    @Test
    fun `throws for unsupported provider`() {
        val service = DefaultSocialLoginService(emptyList(), object : SocialAccountService {
            override fun findOrCreate(identity: SocialIdentity): UserPrincipal = error("unused")
        })

        val error = assertFailsWith<IllegalArgumentException> {
            service.authenticate("wechat", "demo-code")
        }

        assertEquals("auth.social.provider.unsupported", error.message)
    }
}
