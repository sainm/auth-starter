package org.sainm.auth.social.wechat

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialIdentity
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets

class WechatCodeSocialAuthProvider(
    private val appId: String,
    private val appSecret: String,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val objectMapper: ObjectMapper = ObjectMapper()
) : SocialAuthProvider {

    override val provider: String = "WECHAT"

    override fun resolve(authCode: String): SocialIdentity {
        val normalizedCode = authCode.trim()
        require(normalizedCode.isNotBlank()) { "authCode must not be blank" }

        val response = exchangeCode(normalizedCode)
        val openId = response.path("openid").asText("").trim()
        val unionId = response.path("unionid").asText("").trim()
        if (openId.isBlank()) {
            val message = response.path("errmsg").asText("Missing openid from WeChat response")
            throw IllegalArgumentException(message)
        }

        return SocialIdentity(
            provider = provider,
            externalId = unionId.ifBlank { openId },
            displayName = response.path("nickname").asText("WeChat User").trim().ifBlank { "WeChat User" }
        )
    }

    private fun exchangeCode(code: String): JsonNode {
        val uri = URI.create(
            buildString {
                append("https://api.weixin.qq.com/sns/oauth2/access_token")
                append("?appid=").append(appId.urlEncode())
                append("&secret=").append(appSecret.urlEncode())
                append("&code=").append(code.urlEncode())
                append("&grant_type=authorization_code")
            }
        )
        val request = HttpRequest.newBuilder(uri)
            .GET()
            .header("Accept", "application/json")
            .build()
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
        if (response.statusCode() !in 200..299) {
            throw IllegalStateException("WeChat auth request failed with status ${response.statusCode()}")
        }
        val payload = objectMapper.readTree(response.body())
        if (payload.hasNonNull("errcode") && payload.path("errcode").asInt() != 0) {
            val errCode = payload.path("errcode").asInt()
            val errMsg = payload.path("errmsg").asText("Unknown WeChat auth error")
            throw IllegalArgumentException("WeChat auth error $errCode: $errMsg")
        }
        return payload
    }

    private fun String.urlEncode(): String = URLEncoder.encode(this, StandardCharsets.UTF_8)
}
