package org.sainm.auth.core.exception

open class AuthException(
    message: String,
    val code: String
) : RuntimeException(message)

class InvalidCredentialsException(
    message: String = "用户名或密码错误"
) : AuthException(message, "AUTH_401001")

class AuthenticatedUserNotFoundException(
    message: String = "当前登录用户不存在"
) : AuthException(message, "AUTH_401004")

class UserAlreadyExistsException(
    message: String = "用户已存在"
) : AuthException(message, "AUTH_409001")

class InvalidTokenException(
    message: String = "令牌无效或已失效"
) : AuthException(message, "AUTH_401002")

class AccountLockedException(
    message: String = "账户已锁定"
) : AuthException(message, "AUTH_401003")

class PasswordValidationException(
    message: String = "密码不符合安全要求"
) : AuthException(message, "AUTH_400003")
