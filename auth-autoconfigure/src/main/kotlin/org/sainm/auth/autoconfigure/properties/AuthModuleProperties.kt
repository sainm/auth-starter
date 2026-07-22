package org.sainm.auth.autoconfigure.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "auth-module")
data class AuthModuleProperties(
    val enabled: Boolean = true,
    val organization: OrganizationProperties = OrganizationProperties(),
    val authentication: AuthenticationProperties = AuthenticationProperties(),
    val registration: RegistrationProperties = RegistrationProperties(),
    val social: SocialProperties = SocialProperties(),
    val sso: SsoProperties = SsoProperties(),
    val email: EmailProperties = EmailProperties(),
    val qrLogin: QrLoginProperties = QrLoginProperties(),
    val performance: PerformanceProperties = PerformanceProperties(),
    val audit: AuditProperties = AuditProperties(),
    val security: SecurityProperties = SecurityProperties(),
    val deviceGovernance: DeviceGovernanceProperties = DeviceGovernanceProperties()
)

data class OrganizationProperties(
    val mode: OrganizationMode = OrganizationMode.BASIC,
    val tenantEnabled: Boolean = false
)

data class AuthenticationProperties(
    val enabledTypes: Set<String> = setOf("PASSWORD", "GOOGLE", "WECHAT")
)

data class RegistrationProperties(
    val selfServiceEnabled: Boolean = false
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
    val appSecret: String? = null,
    /** WeChat MP template IDs for notification delivery. */
    val templateIds: WechatTemplateIdProperties = WechatTemplateIdProperties()
)

data class WechatTemplateIdProperties(
    val taskRemind: String? = null,
    val warningAlert: String? = null,
    val appointmentResult: String? = null
)

data class SsoProperties(
    /** Absolute base URL of THIS service, used to build the IdP callback URL. */
    val callbackBaseUrl: String? = null,
    /** Frontend page that receives the one-time ticket and exchanges it for tokens. */
    val frontendCallbackUrl: String? = null,
    val stateTtlSeconds: Long = 300,
    val ticketTtlSeconds: Long = 120,
    val oidc: OidcSsoProperties = OidcSsoProperties(),
    val cas: CasSsoProperties = CasSsoProperties()
)

data class OidcSsoProperties(
    val enabled: Boolean = false,
    val issuer: String? = null,
    val authorizationEndpoint: String? = null,
    val tokenEndpoint: String? = null,
    val jwkSetUri: String? = null,
    val userInfoEndpoint: String? = null,
    val clientId: String? = null,
    val clientSecret: String? = null,
    val scopes: List<String> = listOf("openid", "profile", "email"),
    val usernameClaim: String = "sub",
    val displayNameClaim: String = "name",
    val emailClaim: String = "email"
)

data class CasSsoProperties(
    val enabled: Boolean = false,
    val serverUrl: String? = null,
    val principalAttribute: String? = null,
    val displayNameAttribute: String? = "displayName",
    val emailAttribute: String? = "mail"
)

data class SecurityProperties(
    val jwt: JwtProperties = JwtProperties(),
    val password: PasswordProperties = PasswordProperties(),
    val lockStrategy: LockStrategyProperties = LockStrategyProperties()
)

data class EmailProperties(
    /** Token TTL for email verification links (seconds). Default 24 h. */
    val verifyTokenTtlSeconds: Long = 86400,
    /** Max resend requests per email address per hour (advisory; enforced by gateway). */
    val maxResendPerHour: Int = 3,
    /** Subject line for the activation email. */
    val activationSubject: String = "Activate your account",
    /** Base URL prepended to the verification token link, e.g. https://psy.school.edu.cn */
    val activationBaseUrl: String? = null
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

data class DeviceGovernanceProperties(
    val deviceStaleDays: Long = 30,
    val sessionStaleDays: Long = 30,
    val requiredPushTokenDeviceTypes: Set<String> = setOf("ANDROID", "IOS"),
    val signalPolicies: DeviceGovernanceSignalPoliciesProperties = DeviceGovernanceSignalPoliciesProperties()
)

data class DeviceGovernanceSignalPoliciesProperties(
    val deviceInactive: DeviceGovernanceSignalPolicyProperties = DeviceGovernanceSignalPolicyProperties(),
    val pushTokenMissing: DeviceGovernanceSignalPolicyProperties = DeviceGovernanceSignalPolicyProperties(),
    val authSessionMissing: DeviceGovernanceSignalPolicyProperties = DeviceGovernanceSignalPolicyProperties(),
    val abnormalAuthSessionStatus: DeviceGovernanceSignalPolicyProperties = DeviceGovernanceSignalPolicyProperties(),
    val authSessionStale: DeviceGovernanceSignalPolicyProperties = DeviceGovernanceSignalPolicyProperties(
        riskLevel = "HIGH",
        autoDisposition = "REVOKE_DEVICE_SESSIONS"
    ),
    val deviceStale: DeviceGovernanceSignalPolicyProperties = DeviceGovernanceSignalPolicyProperties(
        riskLevel = "HIGH",
        autoDisposition = "REVIEW_ONLY"
    ),
    val inactiveDeviceWithActiveSession: DeviceGovernanceSignalPolicyProperties = DeviceGovernanceSignalPolicyProperties(
        riskLevel = "CRITICAL",
        autoDisposition = "REVOKE_DEVICE_SESSIONS"
    ),
    val activeDeviceWithoutActiveSession: DeviceGovernanceSignalPolicyProperties = DeviceGovernanceSignalPolicyProperties(
        riskLevel = "HIGH",
        autoDisposition = "REVIEW_ONLY"
    )
)

data class DeviceGovernanceSignalPolicyProperties(
    val enabled: Boolean = true,
    val riskLevel: String = "MEDIUM",
    val autoDisposition: String = "REVIEW_ONLY"
)
