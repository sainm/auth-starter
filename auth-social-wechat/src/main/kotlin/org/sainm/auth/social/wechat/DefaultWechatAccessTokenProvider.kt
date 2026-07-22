package org.sainm.auth.social.wechat

import com.fasterxml.jackson.databind.ObjectMapper
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.locks.ReentrantLock

/**
 * Default in-memory [WechatAccessTokenProvider]. Fetches and caches the access_token
 * from the WeChat API (`/cgi-bin/token`). Thread-safe via [ReentrantLock].
 * For multi-instance production, override with a Redis-backed implementation.
 */
class DefaultWechatAccessTokenProvider(
    private val appId: String,
    private val appSecret: String,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val objectMapper: ObjectMapper = ObjectMapper()
) : WechatAccessTokenProvider {

    @Volatile
    private var cached: WechatAccessToken? = null
    private val lock = ReentrantLock()

    override fun getToken(): WechatAccessToken {
        val current = cached
        if (current != null && !current.isExpired) return current

        lock.lock()
        try {
            val doubleCheck = cached
            if (doubleCheck != null && !doubleCheck.isExpired) return doubleCheck
            val newToken = fetch()
            cached = newToken
            return newToken
        } finally {
            lock.unlock()
        }
    }

    private fun fetch(): WechatAccessToken {
        val uri = URI.create(
            "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=$appId&secret=$appSecret"
        )
        val request = HttpRequest.newBuilder(uri).GET()
            .header("Accept", "application/json").build()
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
        check(response.statusCode() in 200..299) { "WeChat token http ${response.statusCode()}" }
        val root = objectMapper.readTree(response.body())
        val accessToken = root.path("access_token").asText("").trim()
        require(accessToken.isNotBlank()) {
            "WeChat access_token missing: errcode=${root.path("errcode").asInt()} errmsg=${root.path("errmsg").asText()}"
        }
        val expiresIn = root.path("expires_in").asLong(7200)
        return WechatAccessToken(
            token = accessToken,
            expiresAtEpochSecond = Instant.now().epochSecond + expiresIn
        )
    }
}
