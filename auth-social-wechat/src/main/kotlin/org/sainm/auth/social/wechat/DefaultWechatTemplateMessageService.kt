package org.sainm.auth.social.wechat

import com.fasterxml.jackson.databind.ObjectMapper
import org.sainm.auth.core.spi.WechatTemplateMessageService
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets

/**
 * Default [WechatTemplateMessageService] calling the WeChat MP template-send API.
 * Uses [WechatAccessTokenProvider] for the cached access_token.
 */
class DefaultWechatTemplateMessageService(
    private val tokenProvider: WechatAccessTokenProvider,
    private val httpClient: HttpClient = HttpClient.newHttpClient(),
    private val objectMapper: ObjectMapper = ObjectMapper()
) : WechatTemplateMessageService {

    private val log = LoggerFactory.getLogger(DefaultWechatTemplateMessageService::class.java)

    override fun send(openId: String, templateId: String, data: Map<String, Any?>) {
        val token = tokenProvider.getToken()
        val payload = objectMapper.writeValueAsString(
            mapOf(
                "touser" to openId,
                "template_id" to templateId,
                "data" to data
            )
        )
        val request = HttpRequest.newBuilder(
            URI.create(
                "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=${token.token}"
            )
        )
            .header("Content-Type", "application/json; charset=UTF-8")
            .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
            .build()
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
        if (response.statusCode() !in 200..299) {
            log.warn("WeChat template send http {}: {}", response.statusCode(), response.body())
            return
        }
        val root = objectMapper.readTree(response.body())
        val errCode = root.path("errcode").asInt()
        if (errCode != 0) {
            log.warn("WeChat template send errcode={} errmsg={}", errCode, root.path("errmsg").asText())
        }
    }
}
