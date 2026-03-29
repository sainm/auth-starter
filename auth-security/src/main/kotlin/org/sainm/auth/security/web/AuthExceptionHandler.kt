package org.sainm.auth.security.web

import org.sainm.auth.core.exception.AuthException
import org.sainm.auth.security.api.ApiResponse
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.AccessDeniedException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class AuthExceptionHandler {

    @ExceptionHandler(AuthException::class)
    fun handleAuthException(ex: AuthException): ResponseEntity<ApiResponse<Nothing>> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiResponse(ex.code, ex.message ?: "Unauthorized", null))

    @ExceptionHandler(AccessDeniedException::class)
    fun handleAccessDenied(ex: AccessDeniedException): ResponseEntity<ApiResponse<Nothing>> =
        ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse("AUTH_403001", ex.message ?: "Forbidden", null))

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(ex: MethodArgumentNotValidException): ResponseEntity<ApiResponse<Nothing>> {
        val message = ex.bindingResult.fieldErrors.firstOrNull()?.defaultMessage ?: "请求参数校验失败"
        return ResponseEntity.badRequest().body(ApiResponse("AUTH_400001", message, null))
    }

    @ExceptionHandler(IllegalArgumentException::class)
    fun handleIllegalArgument(ex: IllegalArgumentException): ResponseEntity<ApiResponse<Nothing>> =
        ResponseEntity.badRequest()
            .body(ApiResponse("AUTH_400002", ex.message ?: "Bad request", null))
}
