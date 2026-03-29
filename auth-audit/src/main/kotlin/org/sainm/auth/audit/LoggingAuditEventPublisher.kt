package org.sainm.auth.audit

import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.slf4j.LoggerFactory

class LoggingAuditEventPublisher : AuditEventPublisher {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun publish(event: AuditEvent) {
        log.info(
            "audit-event type={} userId={} principal={} detail={}",
            event.type,
            event.userId,
            event.principal,
            event.detail
        )
    }
}
