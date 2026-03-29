package org.sainm.auth.autoconfigure.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "auth-module")
data class AuthModuleProperties(
    val enabled: Boolean = true,
    val organization: OrganizationProperties = OrganizationProperties(),
    val authentication: AuthenticationProperties = AuthenticationProperties(),
    val social: SocialProperties = SocialProperties(),
    val qrLogin: QrLoginProperties = QrLoginProperties(),
    val performance: PerformanceProperties = PerformanceProperties(),
    val audit: AuditProperties = AuditProperties(),
    val security: SecurityProperties = SecurityProperties()
)

data class OrganizationProperties(
    val mode: OrganizationMode = OrganizationMode.BASIC,
    val tenantEnabled: Boolean = false
)

data class AuthenticationProperties(
    val enabledTypes: Set<String> = setOf("PASSWORD", "GOOGLE", "WECHAT")
)

data class SocialProperties(
    val google: GoogleSocialProperties = GoogleSocialProperties(),
    val wechat: WechatSocialProperties = WechatSocialProperties()
)

data class GoogleSocialProperties(
    val enabled: Boolean = false,
    val clientId: String? = null
)

data class WechatSocialProperties(
    val enabled: Boolean = false,
    val appId: String? = null,
    val appSecret: String? = null
)

data class SecurityProperties(
    val jwt: JwtProperties = JwtProperties(),
    val password: PasswordProperties = PasswordProperties(),
    val lockStrategy: LockStrategyProperties = LockStrategyProperties()
)

data class JwtProperties(
    val secret: String = "change-me-change-me-change-me-change-me",
    val issuer: String = "auth-module",
    val accessTokenExpireMinutes: Long = 30,
    val refreshTokenExpireDays: Long = 7
)

data class PasswordProperties(
    val encoder: String = "argon2",
    val minLength: Int = 8
)

data class LockStrategyProperties(
    val maxAttempts: Int = 5,
    val lockDurationMinutes: Long = 30,
    val ipMaxAttempts: Int = 20,
    val captchaThreshold: Int = 3
)

data class QrLoginProperties(
    val enabled: Boolean = true,
    val ttlSeconds: Long = 180,
    val transport: String = "http-polling"
)

data class PerformanceProperties(
    val virtualThreads: VirtualThreadProperties = VirtualThreadProperties()
)

data class VirtualThreadProperties(
    val enabled: Boolean = false,
    val authExecutorEnabled: Boolean = false,
    val qrListenerEnabled: Boolean = false
)

data class AuditProperties(
    val enabled: Boolean = true,
    val recordSuccessLogins: Boolean = true,
    val recordFailedLogins: Boolean = true,
    val recordAccessDenied: Boolean = true
)

enum class OrganizationMode {
    BASIC,
    GROUP,
    TENANT
}
