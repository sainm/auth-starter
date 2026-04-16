package org.sainm.auth.core.exception

open class AuthException(
    messageKey: String,
    val code: String,
    vararg val messageArgs: Any
) : RuntimeException(messageKey)

class InvalidCredentialsException(
    messageKey: String = "auth.invalidCredentials"
) : AuthException(messageKey, "AUTH_401001")

class AuthenticatedUserNotFoundException(
    messageKey: String = "auth.authenticatedUserNotFound"
) : AuthException(messageKey, "AUTH_401004")

class UserAlreadyExistsException(
    messageKey: String = "auth.userAlreadyExists"
) : AuthException(messageKey, "AUTH_409001")

class InvalidTokenException(
    messageKey: String = "auth.invalidToken"
) : AuthException(messageKey, "AUTH_401002")

class AccountLockedException(
    messageKey: String = "auth.accountLocked"
) : AuthException(messageKey, "AUTH_401003")

class PasswordValidationException(
    messageKey: String = "auth.password.validation",
    vararg messageArgs: Any
) : AuthException(
    if (messageKey.startsWith("auth.")) messageKey else "auth.password.validation",
    "AUTH_400003",
    *messageArgs
)

class SessionManagementException(
    messageKey: String = "auth.session.invalid",
    vararg messageArgs: Any
) : AuthException(
    if (messageKey.startsWith("auth.")) messageKey else "auth.session.invalid",
    "AUTH_401005",
    *messageArgs
)
