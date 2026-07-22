package org.sainm.auth.security.service

import org.sainm.auth.core.spi.MailSenderService
import org.slf4j.LoggerFactory

/**
 * No-op [MailSenderService] — logs the would-be email at WARN level.
 * Replace with a real implementation (SMTP, SendGrid, etc.) in production.
 */
class NoOpMailSenderService : MailSenderService {
    private val log = LoggerFactory.getLogger(NoOpMailSenderService::class.java)

    override fun send(to: String, subject: String, bodyHtml: String) {
        log.warn(
            "auth-starter: MailSenderService not configured — email to [{}] subject [{}] was dropped. " +
                "Provide a MailSenderService bean to enable real email delivery.",
            to, subject
        )
    }
}
