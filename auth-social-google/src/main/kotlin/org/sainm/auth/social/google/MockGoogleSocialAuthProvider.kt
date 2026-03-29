package org.sainm.auth.social.google

import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialIdentity

class MockGoogleSocialAuthProvider : SocialAuthProvider {
    override val provider: String = "GOOGLE"

    override fun resolve(authCode: String): SocialIdentity {
        val normalized = authCode.trim()
        require(normalized.isNotBlank()) { "authCode must not be blank" }
        return SocialIdentity(
            provider = provider,
            externalId = normalized,
            displayName = "Google User",
            email = "$normalized@example.test"
        )
    }
}
