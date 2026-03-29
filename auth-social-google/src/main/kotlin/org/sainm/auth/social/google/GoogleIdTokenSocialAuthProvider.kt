package org.sainm.auth.social.google

import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport
import com.google.api.client.json.gson.GsonFactory
import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialIdentity

class GoogleIdTokenSocialAuthProvider(
    clientId: String
) : SocialAuthProvider {

    override val provider: String = "GOOGLE"

    private val verifier: GoogleIdTokenVerifier = GoogleIdTokenVerifier.Builder(
        GoogleNetHttpTransport.newTrustedTransport(),
        GsonFactory.getDefaultInstance()
    )
        .setAudience(listOf(clientId))
        .build()

    override fun resolve(authCode: String): SocialIdentity {
        val token = authCode.trim()
        require(token.isNotBlank()) { "idToken must not be blank" }
        val idToken = verifier.verify(token) ?: throw IllegalArgumentException("Invalid Google ID token")
        val payload = idToken.payload
        return SocialIdentity(
            provider = provider,
            externalId = payload.subject,
            displayName = payload["name"] as? String,
            email = payload.email
        )
    }
}
