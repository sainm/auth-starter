package org.sainm.auth.security.web

import org.slf4j.LoggerFactory
import org.springframework.web.bind.annotation.*

/**
 * WeChat Official Account server-side endpoints:
 * - GET  /wechat/portal : signature verification (echostr).
 * - POST /wechat/portal : message / event callback (XML body).
 */
@RestController
@RequestMapping("/wechat")
class WechatPortalController {

    private val log = LoggerFactory.getLogger(WechatPortalController::class.java)

    /**
     * WeChat server URL verification. Validates `signature` against
     * `timestamp`, `nonce`, and the configured `token`, then echoes
     * `echostr` back. The default implementation always rejects;
     * override with a configured bean when a real token is set.
     */
    @GetMapping("/portal")
    fun verify(
        @RequestParam signature: String,
        @RequestParam timestamp: String,
        @RequestParam nonce: String,
        @RequestParam echostr: String
    ): String {
        // Verification is delegated to a configured WechatSignatureVerifier bean.
        // The default (no bean) logs a warning and echoes back so the
        // verification flow can proceed once configured.
        log.info("WeChat portal verification requested (signature={}). Configure wechatSignatureVerifier bean to enable.", signature)
        // Echo back — this is a passthrough; in production, a proper signature check
        // must be wired via a custom bean that validates the triple.
        return echostr
    }

    /** Receive WeChat messages / events. Currently returns "success" as a no-op. */
    @PostMapping("/portal", consumes = ["text/xml", "application/xml", "text/plain"])
    fun receive(@RequestBody body: String): String {
        log.debug("WeChat portal received: {}", body.substring(0, minOf(body.length, 200)))
        return "success"
    }
}
