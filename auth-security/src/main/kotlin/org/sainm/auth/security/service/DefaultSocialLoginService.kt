package org.sainm.auth.security.service

import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.spi.SocialAccountService
import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialLoginService

class DefaultSocialLoginService(
    providers: List<SocialAuthProvider>,
    private val socialAccountService: SocialAccountService
) : SocialLoginService {

    private val providersByName = providers.associateBy { it.provider.uppercase() }

    override fun authenticate(provider: String, authCode: String): UserPrincipal {
        val authProvider = providersByName[provider.uppercase()]
            ?: throw IllegalArgumentException("Unsupported social provider: $provider")
        val identity = authProvider.resolve(authCode)
        return socialAccountService.findOrCreate(identity)
    }
}
