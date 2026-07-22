package org.sainm.auth.sso

import com.fasterxml.jackson.databind.ObjectMapper
import org.sainm.auth.core.spi.SocialIdentity
import org.sainm.auth.core.spi.SsoAuthProvider
import org.sainm.auth.core.spi.SsoAuthorizationRequest
import org.sainm.auth.core.spi.SsoCallback
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets

/**
 * CAS protocol provider. Redirects to `${serverUrl}/login?service=...` and, on
 * callback, validates the ticket via `${serverUrl}/p3/serviceValidate` (JSON
 * format) mapping the returned user + attributes to a [SocialIdentity].
 */
class CasSsoAuthProvider(
    private val config: CasProviderConfig,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val objectMapper: ObjectMapper = ObjectMapper()
) : SsoAuthProvider {

    override val provider: String = "CAS"

    override fun buildAuthorizationUrl(request: SsoAuthorizationRequest): String =
        buildString {
            append(config.serverUrl.trimEnd('/'))
            append("/login?service=").append(request.redirectUri.enc())
        }

    override fun resolve(authCode: String): SocialIdentity =
        resolve(SsoCallback(authCode = authCode))

    override fun resolve(callback: SsoCallback): SocialIdentity {
        val ticket = callback.authCode.trim()
        require(ticket.isNotBlank()) { "auth.sso.cas.ticket.blank" }
        val service = callback.redirectUri
            ?: throw IllegalArgumentException("auth.sso.cas.service.missing")

        val validateUri = buildString {
            append(config.serverUrl.trimEnd('/'))
            append("/p3/serviceValidate")
            append("?ticket=").append(ticket.enc())
            append("&service=").append(service.enc())
            append("&format=JSON")
        }
        val request = HttpRequest.newBuilder(URI.create(validateUri))
            .header("Accept", "application/json")
            .GET()
            .build()
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
        if (response.statusCode() !in 200..299) {
            throw IllegalStateException("auth.sso.cas.validate.http.${response.statusCode()}")
        }

        val root = objectMapper.readTree(response.body()).path("serviceResponse")
        val failure = root.path("authenticationFailure")
        if (!failure.isMissingNode && !failure.isNull) {
            val code = failure.path("code").asText("UNKNOWN")
            throw IllegalArgumentException("auth.sso.cas.validate.failure.$code")
        }
        val success = root.path("authenticationSuccess")
        if (success.isMissingNode || success.isNull) {
            throw IllegalArgumentException("auth.sso.cas.validate.noSuccess")
        }

        val user = success.path("user").asText("").trim()
        if (user.isBlank()) {
            throw IllegalArgumentException("auth.sso.cas.user.missing")
        }
        val attributes = success.path("attributes")
        val principalKey = config.principalAttribute
            ?.let { attributes.path(it).takeUnless(com.fasterxml.jackson.databind.JsonNode::isMissingNode) }
            ?.let { if (it.isArray && it.size() > 0) it.get(0).asText() else it.asText() }
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?: user

        val displayName = config.displayNameAttribute?.let { attributes.path(it).firstScalar() }
        val email = config.emailAttribute?.let { attributes.path(it).firstScalar() }

        return SocialIdentity(
            provider = provider,
            externalId = principalKey,
            displayName = displayName,
            email = email,
            attributes = mapOf("casUser" to user)
        )
    }

    private fun com.fasterxml.jackson.databind.JsonNode.firstScalar(): String? {
        if (isMissingNode || isNull) return null
        val node = if (isArray && size() > 0) get(0) else this
        return node.asText("").trim().takeIf { it.isNotBlank() }
    }

    private fun String.enc(): String = URLEncoder.encode(this, StandardCharsets.UTF_8)
}
