package org.sainm.auth.sso

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.sainm.auth.core.spi.SocialIdentity
import org.sainm.auth.core.spi.SsoAuthProvider
import org.sainm.auth.core.spi.SsoAuthorizationRequest
import org.sainm.auth.core.spi.SsoCallback
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets

/**
 * OIDC authorization-code provider. Builds the authorize redirect and, on
 * callback, exchanges the code for an id_token which is validated against the
 * IdP JWKS before claims are mapped to a [SocialIdentity].
 */
class OidcSsoAuthProvider(
    private val config: OidcProviderConfig,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val objectMapper: ObjectMapper = ObjectMapper()
) : SsoAuthProvider {

    override val provider: String = "OIDC"

    private val jwtProcessor: DefaultJWTProcessor<SecurityContext> = DefaultJWTProcessor<SecurityContext>().apply {
        val keySource = RemoteJWKSet<SecurityContext>(URL(config.jwkSetUri))
        jwsKeySelector = JWSVerificationKeySelector(
            com.nimbusds.jose.JWSAlgorithm.RS256,
            keySource
        )
    }

    override fun buildAuthorizationUrl(request: SsoAuthorizationRequest): String =
        buildString {
            append(config.authorizationEndpoint)
            append(if (config.authorizationEndpoint.contains('?')) "&" else "?")
            append("response_type=code")
            append("&client_id=").append(config.clientId.enc())
            append("&redirect_uri=").append(request.redirectUri.enc())
            append("&scope=").append(config.scopes.joinToString(" ").enc())
            append("&state=").append(request.state.enc())
            request.nonce?.let { append("&nonce=").append(it.enc()) }
        }

    override fun resolve(authCode: String): SocialIdentity =
        resolve(SsoCallback(authCode = authCode))

    override fun resolve(callback: SsoCallback): SocialIdentity {
        val code = callback.authCode.trim()
        require(code.isNotBlank()) { "auth.sso.oidc.code.blank" }
        val redirectUri = callback.redirectUri
            ?: throw IllegalArgumentException("auth.sso.oidc.redirectUri.missing")

        val tokenResponse = exchangeCode(code, redirectUri)
        val idToken = tokenResponse.path("id_token").asText("").trim()
        if (idToken.isBlank()) {
            throw IllegalArgumentException("auth.sso.oidc.idToken.missing")
        }

        val claims = try {
            jwtProcessor.process(idToken, null)
        } catch (ex: Exception) {
            throw IllegalArgumentException("auth.sso.oidc.idToken.invalid", ex)
        }

        // Validate issuer and audience.
        if (claims.issuer != null && claims.issuer != config.issuer) {
            throw IllegalArgumentException("auth.sso.oidc.issuer.mismatch")
        }
        if (claims.audience != null && claims.audience.isNotEmpty() && config.clientId !in claims.audience) {
            throw IllegalArgumentException("auth.sso.oidc.audience.mismatch")
        }
        // Validate nonce when one was issued.
        val expectedNonce = callback.nonce
        if (expectedNonce != null) {
            val actualNonce = claims.getStringClaim("nonce")
            if (actualNonce != expectedNonce) {
                throw IllegalArgumentException("auth.sso.oidc.nonce.mismatch")
            }
        }

        val externalId = claims.getStringClaim(config.usernameClaim)?.trim()
            ?: claims.subject?.trim()
            ?: throw IllegalArgumentException("auth.sso.oidc.principal.missing")
        val displayName = claims.getStringClaim(config.displayNameClaim)?.trim()
        val email = claims.getStringClaim(config.emailClaim)?.trim()

        return SocialIdentity(
            provider = provider,
            externalId = externalId,
            displayName = displayName,
            email = email,
            attributes = mapOf(
                "sub" to claims.subject,
                "iss" to claims.issuer
            )
        )
    }

    private fun exchangeCode(code: String, redirectUri: String): JsonNode {
        val form = buildString {
            append("grant_type=authorization_code")
            append("&code=").append(code.enc())
            append("&redirect_uri=").append(redirectUri.enc())
            append("&client_id=").append(config.clientId.enc())
            append("&client_secret=").append(config.clientSecret.enc())
        }
        val request = HttpRequest.newBuilder(URI.create(config.tokenEndpoint))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
            .build()
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
        if (response.statusCode() !in 200..299) {
            throw IllegalStateException("auth.sso.oidc.token.http.${response.statusCode()}")
        }
        return objectMapper.readTree(response.body())
    }

    private fun String.enc(): String = URLEncoder.encode(this, StandardCharsets.UTF_8)
}
