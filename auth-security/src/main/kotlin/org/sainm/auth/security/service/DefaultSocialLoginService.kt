package org.sainm.auth.security.service

import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.spi.SocialAccountService
import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialLoginService
import org.sainm.auth.core.spi.SsoCallback

class DefaultSocialLoginService(
    providers: List<SocialAuthProvider>,
    private val socialAccountService: SocialAccountService
) : SocialLoginService {

    private val providersByName = providers.associateBy { it.provider.uppercase() }

    override fun authenticate(provider: String, authCode: String): UserPrincipal {
        val authProvider = requireProvider(provider)
        val identity = authProvider.resolve(authCode)
        return socialAccountService.findOrCreate(identity)
    }

    override fun authenticate(provider: String, callback: SsoCallback): UserPrincipal {
        val authProvider = requireProvider(provider)
        val identity = authProvider.resolve(callback)
        return socialAccountService.findOrCreate(identity)
    }

    private fun requireProvider(provider: String): SocialAuthProvider =
        providersByName[provider.uppercase()]
            ?: throw IllegalArgumentException("auth.social.provider.unsupported")
}
