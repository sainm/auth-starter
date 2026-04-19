package org.sainm.auth.autoconfigure

import com.fasterxml.jackson.databind.ObjectMapper
import org.sainm.auth.audit.LoggingAuditEventPublisher
import org.sainm.auth.autoconfigure.properties.AuthModuleProperties
import org.sainm.auth.core.domain.LoginCommand
import org.sainm.auth.core.domain.PasswordLoginCommand
import org.sainm.auth.core.device.DefaultDeviceGovernanceEvaluator
import org.sainm.auth.core.device.DeviceGovernanceEvaluator
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.core.spi.AuditQueryService
import org.sainm.auth.core.spi.AuthenticationHandler
import org.sainm.auth.core.spi.DeviceGovernanceService
import org.sainm.auth.core.spi.LoginAttemptService
import org.sainm.auth.core.spi.OrganizationService
import org.sainm.auth.core.spi.PasswordManagementService
import org.sainm.auth.core.spi.PermissionService
import org.sainm.auth.core.spi.QrLoginService
import org.sainm.auth.core.spi.SessionManagementService
import org.sainm.auth.core.spi.SocialAccountService
import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialLoginService
import org.sainm.auth.core.spi.TokenBlacklistService
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserAdminService
import org.sainm.auth.core.spi.UserRegistrationService
import org.sainm.auth.core.spi.UserLookupService
import org.sainm.auth.persistence.JdbcAuditEventPublisher
import org.sainm.auth.persistence.JdbcAuditQueryService
import org.sainm.auth.persistence.JdbcLoginAttemptService
import org.sainm.auth.persistence.JdbcOrganizationService
import org.sainm.auth.persistence.JdbcPasswordManagementService
import org.sainm.auth.persistence.JdbcPermissionService
import org.sainm.auth.persistence.JdbcSessionManagementService
import org.sainm.auth.persistence.JdbcSocialAccountService
import org.sainm.auth.persistence.JdbcTokenBlacklistService
import org.sainm.auth.persistence.JdbcUserAdminService
import org.sainm.auth.persistence.JdbcUserRegistrationService
import org.sainm.auth.persistence.JdbcUserLookupService
import org.sainm.auth.qr.JdbcQrLoginService
import org.sainm.auth.security.config.AuthSecurityConfiguration
import org.sainm.auth.security.handler.AuthenticationDispatcher
import org.sainm.auth.security.handler.PasswordAuthenticationHandler
import org.sainm.auth.security.service.DefaultSocialLoginService
import org.sainm.auth.security.support.CurrentUserFacade
import org.sainm.auth.social.google.GoogleIdTokenSocialAuthProvider
import org.sainm.auth.social.google.MockGoogleSocialAuthProvider
import org.sainm.auth.social.wechat.MockWechatSocialAuthProvider
import org.sainm.auth.social.wechat.WechatCodeSocialAuthProvider
import org.sainm.auth.security.token.JwtTokenProperties
import org.sainm.auth.security.token.JwtTokenService
import org.sainm.auth.security.web.AuthController
import org.sainm.auth.security.web.DeviceGovernanceController
import org.sainm.auth.security.web.AuthExceptionHandler
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder

@AutoConfiguration
@ConditionalOnClass(AuthenticationDispatcher::class)
@EnableConfigurationProperties(AuthModuleProperties::class)
@Import(AuthSecurityConfiguration::class, AuthExceptionHandler::class)
@ConditionalOnProperty(prefix = "auth-module", name = ["enabled"], havingValue = "true", matchIfMissing = true)
class AuthModuleAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun authController(
        authenticationDispatcher: AuthenticationDispatcher,
        userLookupService: UserLookupService,
        permissionService: PermissionService,
        tokenService: TokenService,
        userRegistrationService: UserRegistrationService,
        passwordManagementService: PasswordManagementService,
        auditEventPublisher: AuditEventPublisher,
        auditQueryService: AuditQueryService,
        userAdminService: UserAdminService,
        organizationService: OrganizationService,
        sessionManagementServiceProvider: ObjectProvider<SessionManagementService>,
        qrLoginServiceProvider: ObjectProvider<QrLoginService>,
        socialLoginServiceProvider: ObjectProvider<SocialLoginService>,
        properties: AuthModuleProperties
    ): AuthController =
        AuthController(
            authenticationDispatcher = authenticationDispatcher,
            userLookupService = userLookupService,
            permissionService = permissionService,
            tokenService = tokenService,
            userRegistrationService = userRegistrationService,
            passwordManagementService = passwordManagementService,
            auditEventPublisher = auditEventPublisher,
            auditQueryService = auditQueryService,
            userAdminService = userAdminService,
            organizationService = organizationService,
            sessionManagementServiceProvider = sessionManagementServiceProvider,
            qrLoginServiceProvider = qrLoginServiceProvider,
            socialLoginServiceProvider = socialLoginServiceProvider,
            selfRegistrationEnabled = properties.registration.selfServiceEnabled,
            passwordMinLength = properties.security.password.minLength
        )

    @Bean
    @ConditionalOnBean(DeviceGovernanceService::class)
    @ConditionalOnMissingBean
    fun deviceGovernanceController(
        userLookupService: UserLookupService,
        permissionService: PermissionService,
        deviceGovernanceService: DeviceGovernanceService
    ): DeviceGovernanceController =
        DeviceGovernanceController(
            userLookupService = userLookupService,
            permissionService = permissionService,
            deviceGovernanceService = deviceGovernanceService
        )

    @Bean
    @ConditionalOnMissingBean
    fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    @ConditionalOnMissingBean(AuditEventPublisher::class)
    fun auditEventPublisher(
        jdbcTemplateProvider: ObjectProvider<JdbcTemplate>,
        objectMapperProvider: ObjectProvider<ObjectMapper>
    ): AuditEventPublisher {
        val jdbcTemplate = jdbcTemplateProvider.ifAvailable
        val objectMapper = objectMapperProvider.ifAvailable
        return if (jdbcTemplate != null && objectMapper != null) {
            JdbcAuditEventPublisher(jdbcTemplate, objectMapper)
        } else {
            LoggingAuditEventPublisher()
        }
    }

    @Bean
    @ConditionalOnMissingBean
    fun tokenService(
        properties: AuthModuleProperties,
        tokenBlacklistServiceProvider: ObjectProvider<TokenBlacklistService>,
        sessionManagementServiceProvider: ObjectProvider<SessionManagementService>,
        userLookupServiceProvider: ObjectProvider<UserLookupService>
    ): TokenService =
        JwtTokenService(
            JwtTokenProperties(
                secret = properties.security.jwt.secret,
                issuer = properties.security.jwt.issuer,
                accessTokenExpireMinutes = properties.security.jwt.accessTokenExpireMinutes,
                refreshTokenExpireDays = properties.security.jwt.refreshTokenExpireDays
            ),
            tokenBlacklistService = tokenBlacklistServiceProvider.ifAvailable,
            sessionManagementService = sessionManagementServiceProvider.ifAvailable,
            userLookupService = userLookupServiceProvider.ifAvailable
        )

    @Bean
    @ConditionalOnMissingBean
    fun authenticationDispatcher(
        handlers: List<AuthenticationHandler<out LoginCommand>>
    ): AuthenticationDispatcher = AuthenticationDispatcher(handlers)

    @Bean
    @ConditionalOnMissingBean
    fun passwordAuthenticationHandler(
        userLookupService: UserLookupService,
        permissionService: PermissionService,
        tokenService: TokenService,
        passwordEncoder: PasswordEncoder,
        auditEventPublisher: AuditEventPublisher,
        loginAttemptService: LoginAttemptService
    ): AuthenticationHandler<PasswordLoginCommand> =
        PasswordAuthenticationHandler(
            userLookupService = userLookupService,
            permissionService = permissionService,
            tokenService = tokenService,
            passwordEncoder = passwordEncoder,
            auditEventPublisher = auditEventPublisher,
            loginAttemptService = loginAttemptService
        )

    @Bean
    @ConditionalOnMissingBean(UserLookupService::class)
    fun jdbcUserLookupService(jdbcTemplate: JdbcTemplate): UserLookupService =
        JdbcUserLookupService(jdbcTemplate)

    @Bean
    @ConditionalOnMissingBean(PermissionService::class)
    fun jdbcPermissionService(jdbcTemplate: JdbcTemplate): PermissionService =
        JdbcPermissionService(jdbcTemplate)

    @Bean
    @ConditionalOnMissingBean(UserRegistrationService::class)
    fun jdbcUserRegistrationService(
        jdbcTemplate: JdbcTemplate,
        passwordEncoder: PasswordEncoder
    ): JdbcUserRegistrationService = JdbcUserRegistrationService(jdbcTemplate, passwordEncoder)

    @Bean
    @ConditionalOnMissingBean(LoginAttemptService::class)
    fun jdbcLoginAttemptService(properties: AuthModuleProperties, jdbcTemplate: JdbcTemplate): LoginAttemptService =
        JdbcLoginAttemptService(
            jdbcTemplate = jdbcTemplate,
            maxAttempts = properties.security.lockStrategy.maxAttempts,
            lockDurationMinutes = properties.security.lockStrategy.lockDurationMinutes
        )

    @Bean
    @ConditionalOnMissingBean(PasswordManagementService::class)
    fun jdbcPasswordManagementService(
        jdbcTemplate: JdbcTemplate,
        passwordEncoder: PasswordEncoder,
        properties: AuthModuleProperties
    ): PasswordManagementService =
        JdbcPasswordManagementService(
            jdbcTemplate = jdbcTemplate,
            passwordEncoder = passwordEncoder,
            minLength = properties.security.password.minLength
        )

    @Bean
    @ConditionalOnMissingBean(AuditQueryService::class)
    fun jdbcAuditQueryService(jdbcTemplate: JdbcTemplate, objectMapper: ObjectMapper): AuditQueryService =
        JdbcAuditQueryService(jdbcTemplate, objectMapper)

    @Bean
    @ConditionalOnMissingBean(UserAdminService::class)
    fun jdbcUserAdminService(jdbcTemplate: JdbcTemplate): UserAdminService =
        JdbcUserAdminService(jdbcTemplate)

    @Bean
    @ConditionalOnMissingBean(OrganizationService::class)
    fun jdbcOrganizationService(jdbcTemplate: JdbcTemplate): OrganizationService =
        JdbcOrganizationService(jdbcTemplate)

    @Bean
    @ConditionalOnMissingBean(QrLoginService::class)
    @ConditionalOnProperty(prefix = "auth-module.qr-login", name = ["enabled"], havingValue = "true", matchIfMissing = true)
    fun jdbcQrLoginService(
        properties: AuthModuleProperties,
        jdbcTemplate: JdbcTemplate,
        userLookupService: UserLookupService
    ): QrLoginService = JdbcQrLoginService(
        jdbcTemplate = jdbcTemplate,
        userLookupService = userLookupService,
        ttlSeconds = properties.qrLogin.ttlSeconds
    )

    @Bean
    @ConditionalOnMissingBean(SocialAccountService::class)
    fun jdbcSocialAccountService(
        jdbcTemplate: JdbcTemplate,
        userLookupService: UserLookupService,
        userRegistrationService: JdbcUserRegistrationService
    ): SocialAccountService =
        JdbcSocialAccountService(
            jdbcTemplate = jdbcTemplate,
            userLookupService = userLookupService,
            userRegistrationService = userRegistrationService
        )

    @Bean
    @ConditionalOnMissingBean(name = ["googleSocialAuthProvider"])
    fun googleSocialAuthProvider(properties: AuthModuleProperties): SocialAuthProvider =
        if (properties.social.google.enabled && !properties.social.google.clientId.isNullOrBlank()) {
            GoogleIdTokenSocialAuthProvider(properties.social.google.clientId)
        } else {
            MockGoogleSocialAuthProvider()
        }

    @Bean
    @ConditionalOnMissingBean(name = ["wechatSocialAuthProvider"])
    fun wechatSocialAuthProvider(properties: AuthModuleProperties): SocialAuthProvider =
        if (
            properties.social.wechat.enabled &&
            !properties.social.wechat.appId.isNullOrBlank() &&
            !properties.social.wechat.appSecret.isNullOrBlank()
        ) {
            WechatCodeSocialAuthProvider(
                appId = properties.social.wechat.appId,
                appSecret = properties.social.wechat.appSecret
            )
        } else {
            MockWechatSocialAuthProvider()
        }

    @Bean
    @ConditionalOnMissingBean(SocialLoginService::class)
    fun socialLoginService(
        properties: AuthModuleProperties,
        providers: List<SocialAuthProvider>,
        socialAccountService: SocialAccountService
    ): SocialLoginService =
        DefaultSocialLoginService(
            providers = providers.filter { it.provider.uppercase() in properties.authentication.enabledTypes.map(String::uppercase) },
            socialAccountService = socialAccountService
        )

    @Bean
    @ConditionalOnMissingBean(TokenBlacklistService::class)
    fun jdbcTokenBlacklistService(jdbcTemplate: JdbcTemplate): TokenBlacklistService =
        JdbcTokenBlacklistService(jdbcTemplate)

    @Bean
    @ConditionalOnMissingBean(SessionManagementService::class)
    fun jdbcSessionManagementService(jdbcTemplate: JdbcTemplate): SessionManagementService =
        JdbcSessionManagementService(jdbcTemplate)

    @Bean
    @ConditionalOnMissingBean
    fun currentUserFacade(
        userLookupService: UserLookupService,
        permissionService: PermissionService
    ): CurrentUserFacade = CurrentUserFacade(userLookupService, permissionService)

    @Bean
    @ConditionalOnMissingBean(DeviceGovernanceEvaluator::class)
    fun deviceGovernanceEvaluator(): DeviceGovernanceEvaluator = DefaultDeviceGovernanceEvaluator()
}
