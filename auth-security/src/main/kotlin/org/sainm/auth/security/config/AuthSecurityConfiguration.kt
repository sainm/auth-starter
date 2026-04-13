package org.sainm.auth.security.config

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.security.authz.AuthPermissionEvaluator
import org.sainm.auth.security.api.ApiResponse
import org.sainm.auth.security.web.JwtAuthenticationFilter
import org.springframework.context.MessageSource
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.ResourceBundleMessageSource
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import java.util.Locale

@Configuration
@EnableMethodSecurity
class AuthSecurityConfiguration {

    @Bean
    fun messageSource(): ResourceBundleMessageSource =
        ResourceBundleMessageSource().apply {
            setBasenames("messages")
            setDefaultEncoding("UTF-8")
            setFallbackToSystemLocale(false)
        }

    @Bean
    fun authPermissionEvaluator(): AuthPermissionEvaluator = AuthPermissionEvaluator()

    @Bean
    fun jwtAuthenticationFilter(tokenService: TokenService): JwtAuthenticationFilter =
        JwtAuthenticationFilter(tokenService)

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        jwtAuthenticationFilter: JwtAuthenticationFilter,
        accessDeniedHandler: AccessDeniedHandler,
        authenticationEntryPoint: AuthenticationEntryPoint
    ): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .cors(Customizer.withDefaults())
            .httpBasic { it.disable() }
            .formLogin { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .exceptionHandling {
                it.accessDeniedHandler(accessDeniedHandler)
                it.authenticationEntryPoint(authenticationEntryPoint)
            }
            .authorizeHttpRequests {
                it.requestMatchers(HttpMethod.POST, "/auth/login/password").permitAll()
                it.requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
                it.requestMatchers(HttpMethod.POST, "/auth/token/refresh").permitAll()
                it.requestMatchers(HttpMethod.POST, "/auth/social/google").permitAll()
                it.requestMatchers(HttpMethod.POST, "/auth/social/google/mock").permitAll()
                it.requestMatchers(HttpMethod.POST, "/auth/social/wechat").permitAll()
                it.requestMatchers(HttpMethod.POST, "/auth/social/wechat/mock").permitAll()
                it.requestMatchers(HttpMethod.POST, "/auth/qr/scene").permitAll()
                it.requestMatchers(HttpMethod.GET, "/auth/qr/scene/**").permitAll()
                it.requestMatchers(HttpMethod.POST, "/auth/logout").authenticated()
                it.requestMatchers(HttpMethod.POST, "/auth/password/change").authenticated()
                it.requestMatchers(HttpMethod.POST, "/auth/qr/scan").authenticated()
                it.requestMatchers(HttpMethod.POST, "/auth/qr/confirm").authenticated()
                it.requestMatchers(HttpMethod.POST, "/auth/qr/cancel").authenticated()
                it.requestMatchers(HttpMethod.GET, "/auth/admin/**").hasRole("SUPER_ADMIN")
                it.requestMatchers(HttpMethod.POST, "/auth/password/reset").hasAnyRole("ADMIN", "SUPER_ADMIN")
                it.requestMatchers("/auth/users/**", "/auth/roles/**", "/auth/permissions/**", "/auth/groups/**", "/auth/tenants/**")
                    .hasAnyRole("ADMIN", "SUPER_ADMIN")
                it.requestMatchers("/error").permitAll()
                it.anyRequest().authenticated()
            }
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter::class.java)
        return http.build()
    }

    @Bean
    fun accessDeniedHandler(
        auditEventPublisher: AuditEventPublisher,
        messageSource: MessageSource,
        objectMapper: ObjectMapper
    ): AccessDeniedHandler =
        AccessDeniedHandler { request: HttpServletRequest, response: HttpServletResponse, ex ->
            val authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().authentication
            val authenticatedUser = authentication?.credentials as? UserPrincipal
            auditEventPublisher.publish(
                AuditEvent(
                    type = "ACCESS_DENIED",
                    userId = authenticatedUser?.userId ?: (authentication?.principal as? Long),
                    principal = authenticatedUser?.username ?: authentication?.name,
                    detail = mapOf(
                        "path" to request.requestURI,
                        "method" to request.method,
                        "reason" to (ex.message ?: "forbidden")
                    )
                )
            )
            writeJsonError(
                response = response,
                status = HttpServletResponse.SC_FORBIDDEN,
                code = "AUTH_403001",
                message = messageSource.getMessage("auth.accessDenied", null, requestLocale(request)),
                objectMapper = objectMapper
            )
        }

    @Bean
    fun authenticationEntryPoint(
        messageSource: MessageSource,
        objectMapper: ObjectMapper
    ): AuthenticationEntryPoint =
        AuthenticationEntryPoint { request, response, _ ->
            writeJsonError(
                response = response,
                status = HttpServletResponse.SC_UNAUTHORIZED,
                code = "AUTH_401002",
                message = messageSource.getMessage("auth.unauthorized", null, requestLocale(request)),
                objectMapper = objectMapper
            )
        }

    private fun writeJsonError(
        response: HttpServletResponse,
        status: Int,
        code: String,
        message: String,
        objectMapper: ObjectMapper
    ) {
        response.status = status
        response.contentType = "application/json;charset=UTF-8"
        response.writer.write(objectMapper.writeValueAsString(ApiResponse<Nothing?>(code, message, null)))
    }

    private fun requestLocale(request: HttpServletRequest): Locale =
        request.getHeader("Accept-Language")
            ?.takeIf { it.isNotBlank() }
            ?.let(Locale::forLanguageTag)
            ?: request.locale
            ?: Locale.getDefault()
}
