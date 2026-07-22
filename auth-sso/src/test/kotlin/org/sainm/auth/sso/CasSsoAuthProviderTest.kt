package org.sainm.auth.sso

import com.fasterxml.jackson.databind.ObjectMapper
import org.sainm.auth.core.spi.SsoCallback
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class CasSsoAuthProviderTest {

    private val config = CasProviderConfig(
        serverUrl = "https://cas.school.edu.cn/cas",
        principalAttribute = "studentId",
        displayNameAttribute = "displayName",
        emailAttribute = "mail"
    )

    private val objectMapper = ObjectMapper()

    private fun makeProvider(responseBody: String, statusCode: Int = 200): CasSsoAuthProvider {
        @Suppress("UNCHECKED_CAST")
        val httpResponse = mock<HttpResponse<String>>()
        whenever(httpResponse.statusCode()).thenReturn(statusCode)
        whenever(httpResponse.body()).thenReturn(responseBody)

        val httpClient = mock<HttpClient>()
        whenever(httpClient.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<String>>()))
            .thenReturn(httpResponse)

        return CasSsoAuthProvider(config, httpClient, objectMapper)
    }

    @Test
    fun `resolve maps studentId attribute to externalId`() {
        val body = """
        {
          "serviceResponse": {
            "authenticationSuccess": {
              "user": "john",
              "attributes": {
                "studentId": ["20240001"],
                "displayName": ["John Doe"],
                "mail": ["john@school.edu.cn"]
              }
            }
          }
        }
        """.trimIndent()

        val provider = makeProvider(body)
        val identity = provider.resolve(SsoCallback(authCode = "ST-ticket", redirectUri = "https://psy.school.edu.cn/auth/sso/cas/callback"))

        assertEquals("CAS", identity.provider)
        assertEquals("20240001", identity.externalId)
        assertEquals("John Doe", identity.displayName)
        assertEquals("john@school.edu.cn", identity.email)
        assertEquals("john", identity.attributes["casUser"])
    }

    @Test
    fun `resolve falls back to cas user when principalAttribute absent`() {
        val configNoAttr = config.copy(principalAttribute = null)
        val body = """
        {
          "serviceResponse": {
            "authenticationSuccess": {
              "user": "principal_name",
              "attributes": {}
            }
          }
        }
        """.trimIndent()

        @Suppress("UNCHECKED_CAST")
        val httpResponse = mock<HttpResponse<String>>()
        whenever(httpResponse.statusCode()).thenReturn(200)
        whenever(httpResponse.body()).thenReturn(body)
        val httpClient = mock<HttpClient>()
        whenever(httpClient.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<String>>()))
            .thenReturn(httpResponse)

        val provider = CasSsoAuthProvider(configNoAttr, httpClient, objectMapper)
        val identity = provider.resolve(SsoCallback(authCode = "ST-x", redirectUri = "https://example.com/callback"))

        assertEquals("principal_name", identity.externalId)
    }

    @Test
    fun `resolve throws when authenticationFailure is returned`() {
        val body = """
        {
          "serviceResponse": {
            "authenticationFailure": {
              "code": "INVALID_TICKET",
              "description": "Ticket expired"
            }
          }
        }
        """.trimIndent()

        val provider = makeProvider(body)
        val error = assertFailsWith<IllegalArgumentException> {
            provider.resolve(SsoCallback(authCode = "bad", redirectUri = "https://example.com/cb"))
        }
        assertEquals("auth.sso.cas.validate.failure.INVALID_TICKET", error.message)
    }

    @Test
    fun `resolve throws when redirectUri is missing`() {
        val provider = makeProvider("{}")
        assertFailsWith<IllegalArgumentException> {
            provider.resolve(SsoCallback(authCode = "ST-x"))
        }
    }

    @Test
    fun `buildAuthorizationUrl encodes service URL`() {
        val provider = makeProvider("{}")
        val request = org.sainm.auth.core.spi.SsoAuthorizationRequest(
            state = "s1",
            nonce = null,
            redirectUri = "https://psy.school.edu.cn/auth/sso/cas/callback"
        )
        val url = provider.buildAuthorizationUrl(request)
        assert(url.startsWith("https://cas.school.edu.cn/cas/login?service=")) { "Unexpected: $url" }
        assert(url.contains("psy.school.edu.cn")) { "Encoded URI not in URL: $url" }
    }
}
