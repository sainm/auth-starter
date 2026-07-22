package org.sainm.auth.security.service

import org.sainm.auth.core.spi.WechatTemplateMessageService
import org.slf4j.LoggerFactory

class NoOpWechatTemplateMessageService : WechatTemplateMessageService {
    private val log = LoggerFactory.getLogger(NoOpWechatTemplateMessageService::class.java)
    override fun send(openId: String, templateId: String, data: Map<String, Any?>) {
        log.debug("No-op WeChat template message: openId={}, templateId={}", openId, templateId)
    }
}
