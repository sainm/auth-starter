package org.sainm.auth.security.web

import jakarta.servlet.http.HttpServletRequest
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.exception.AuthException
import org.sainm.auth.core.spi.AuditEvent
import org.sainm.auth.core.spi.AuditEventPublisher
import org.sainm.auth.security.api.ApiResponse
import org.springframework.context.MessageSource
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.util.Locale

@RestControllerAdvice
class AuthExceptionHandler(
    private val messageSource: MessageSource,
    private val auditEventPublisher: AuditEventPublisher? = null
) {

    @ExceptionHandler(AuthException::class)
    fun handleAuthException(ex: AuthException, request: HttpServletRequest): ResponseEntity<ApiResponse<Nothing>> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiResponse(ex.code, resolveMessage(ex.message, requestLocale(request), ex.messageArgs), null))

    @ExceptionHandler(AccessDeniedException::class)
    fun handleAccessDenied(ex: AccessDeniedException, request: HttpServletRequest): ResponseEntity<ApiResponse<Nothing>> {
        publishAccessDeniedAudit(request, ex)
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse("AUTH_403001", resolveMessage("auth.accessDenied", requestLocale(request)), null))
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(ex: MethodArgumentNotValidException, request: HttpServletRequest): ResponseEntity<ApiResponse<Nothing>> {
        val message = if (ex.bindingResult.fieldErrors.isNotEmpty()) {
            resolveMessage("auth.validation.notBlank", requestLocale(request))
        } else {
            resolveMessage("auth.validation.failed", requestLocale(request))
        }
        return ResponseEntity.badRequest().body(ApiResponse("AUTH_400001", message, null))
    }

    @ExceptionHandler(IllegalArgumentException::class)
    fun handleIllegalArgument(ex: IllegalArgumentException, request: HttpServletRequest): ResponseEntity<ApiResponse<Nothing>> =
        ResponseEntity.badRequest()
            .body(ApiResponse("AUTH_400002", resolveMessage(ex.message, requestLocale(request), fallback = "Bad request"), null))

    private fun resolveMessage(
        codeOrMessage: String?,
        locale: Locale,
        args: Array<out Any> = emptyArray(),
        fallback: String? = null
    ): String {
        val key = codeOrMessage?.trim().orEmpty()
        if (key.isEmpty()) {
            return fallback ?: resolveMessage("auth.badRequest", locale, emptyArray(), "Bad request")
        }
        return messageSource.getMessage(key, args, fallback ?: key, locale) ?: (fallback ?: key)
    }

    private fun requestLocale(request: HttpServletRequest): Locale {
        val header = request.getHeader("Accept-Language")
            ?.split(",")
            ?.firstOrNull()
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
        return header?.let(Locale::forLanguageTag) ?: request.locale ?: Locale.getDefault()
    }

    private fun publishAccessDeniedAudit(request: HttpServletRequest, ex: AccessDeniedException) {
        val authentication = SecurityContextHolder.getContext().authentication
        val authenticatedUser = authentication?.credentials as? UserPrincipal
        auditEventPublisher?.publish(
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
    }
}
