package org.sainm.auth.social.wechat

import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialIdentity

class MockWechatSocialAuthProvider : SocialAuthProvider {
    override val provider: String = "WECHAT"

    override fun resolve(authCode: String): SocialIdentity {
        val normalized = authCode.trim()
        require(normalized.isNotBlank()) { "authCode must not be blank" }
        return SocialIdentity(
            provider = provider,
            externalId = normalized,
            displayName = "Wechat User"
        )
    }
}
