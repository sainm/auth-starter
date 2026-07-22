package org.sainm.auth.social.wechat

import java.time.Instant

/**
 * Provides a cached WeChat Official Account global access_token.
 * Default implementation stores in memory; override with Redis-backed
 * implementation for multi-instance deployments to avoid concurrent refreshes.
 */
interface WechatAccessTokenProvider {
    fun getToken(): WechatAccessToken
}

data class WechatAccessToken(
    val token: String,
    val expiresAtEpochSecond: Long
) {
    val isExpired: Boolean get() = Instant.now().epochSecond >= expiresAtEpochSecond - 300 // 5-min buffer
}
