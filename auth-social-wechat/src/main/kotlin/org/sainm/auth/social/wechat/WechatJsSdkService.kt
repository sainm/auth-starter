package org.sainm.auth.social.wechat

import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Provides JS-SDK signature config for the WeChat Official Account browser environment.
 */
class WechatJsSdkService(
    private val appId: String,
    private val tokenProvider: WechatAccessTokenProvider,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val objectMapper: ObjectMapper = ObjectMapper()
) {
    private val log = LoggerFactory.getLogger(WechatJsSdkService::class.java)

    @Volatile
    private var ticketCache: Pair<String, Long>? = null // (ticket, expiresAtEpochSecond)

    /**
     * Return { appId, timestamp, nonceStr, signature } for use with wx.config().
     */
    fun config(url: String): Map<String, String> {
        val ticket = getJsApiTicket()
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val nonceStr = java.util.UUID.randomUUID().toString().replace("-", "")
        val raw = "jsapi_ticket=$ticket&noncestr=$nonceStr&timestamp=$timestamp&url=$url"
        val signature = sha1(raw)
        return linkedMapOf(
            "appId" to appId,
            "timestamp" to timestamp,
            "nonceStr" to nonceStr,
            "signature" to signature
        )
    }

    @Synchronized
    private fun getJsApiTicket(): String {
        val cached = ticketCache
        if (cached != null && cached.second - 300 > System.currentTimeMillis() / 1000) return cached.first
        val token = tokenProvider.getToken()
        val uri = URI.create("https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=${token.token}&type=jsapi")
        val request = HttpRequest.newBuilder(uri).GET().header("Accept", "application/json").build()
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
        val root = objectMapper.readTree(response.body())
        val errCode = root.path("errcode").asInt()
        require(errCode == 0) { "JS-SDK ticket errcode=$errCode errmsg=${root.path("errmsg").asText()}" }
        val ticket = root.path("ticket").asText("").trim()
        val expiresIn = root.path("expires_in").asLong(7200)
        ticketCache = ticket to (System.currentTimeMillis() / 1000 + expiresIn)
        return ticket
    }

    private fun sha1(input: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        return digest.digest(input.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
