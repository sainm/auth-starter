package org.sainm.auth.security.web

import org.sainm.auth.social.wechat.WechatJsSdkService
import org.sainm.auth.social.wechat.WechatMenuService
import org.springframework.beans.factory.ObjectProvider
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.*

/**
 * Admin / internal endpoints for WeChat Official Account management.
 * Requires SYS_ADMIN for menu sync; JS-SDK config is semi-public.
 */
@RestController
class WechatManagementController(
    private val menuServiceProvider: ObjectProvider<WechatMenuService>,
    private val jsSdkServiceProvider: ObjectProvider<WechatJsSdkService>
) {

    /** Get JS-SDK signature for a page URL. Called by the frontend wx.config(). */
    @PostMapping("/wechat/jssdk/config")
    fun jssdkConfig(@RequestBody body: Map<String, String>): ResponseEntity<Map<String, String>> {
        val url = body["url"]?.trim()?.takeIf { it.isNotBlank() }
            ?: return ResponseEntity.badRequest().build()
        val service = jsSdkServiceProvider.ifAvailable
            ?: return ResponseEntity.ok(emptyMap())
        return ResponseEntity.ok(service.config(url))
    }

    /** Sync the WeChat custom menu. Menu JSON is posted as the request body. */
    @PostMapping("/api/v1/wechat/menu/sync")
    @PreAuthorize("hasRole('SYS_ADMIN')")
    fun syncMenu(@RequestBody menuJson: String): ResponseEntity<Map<String, String>> {
        val svc = menuServiceProvider.ifAvailable
            ?: return ResponseEntity.ok(mapOf("message" to "WechatMenuService not available"))
        svc.sync(menuJson)
        return ResponseEntity.ok(mapOf("message" to "Menu synced"))
    }
}
