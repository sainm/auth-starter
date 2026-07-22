package org.sainm.auth.social.wechat

import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets

/**
 * Syncs a custom menu to the WeChat Official Account via the MP API.
 * The menu JSON structure is provided by the caller (e.g., from a config file).
 */
class WechatMenuService(
    private val tokenProvider: WechatAccessTokenProvider,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val objectMapper: ObjectMapper = ObjectMapper()
) {
    private val log = LoggerFactory.getLogger(WechatMenuService::class.java)

    fun sync(menuJson: String) {
        val token = tokenProvider.getToken()
        val request = HttpRequest.newBuilder(
            URI.create("https://api.weixin.qq.com/cgi-bin/menu/create?access_token=${token.token}")
        )
            .header("Content-Type", "application/json; charset=UTF-8")
            .POST(HttpRequest.BodyPublishers.ofString(menuJson, StandardCharsets.UTF_8))
            .build()
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
        val root = objectMapper.readTree(response.body())
        val errCode = root.path("errcode").asInt()
        if (errCode != 0) {
            throw IllegalStateException("WeChat menu create errcode=$errCode errmsg=${root.path("errmsg").asText()}")
        }
        log.info("WeChat menu synced successfully")
    }
}
