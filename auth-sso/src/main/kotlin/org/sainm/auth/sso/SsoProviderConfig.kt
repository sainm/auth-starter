package org.sainm.auth.sso

/**
 * Static configuration for an OIDC identity provider.
 */
data class OidcProviderConfig(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val jwkSetUri: String,
    val userInfoEndpoint: String? = null,
    val clientId: String,
    val clientSecret: String,
    val scopes: List<String> = listOf("openid", "profile", "email"),
    /** Claim used as the stable external id / principal key (usually the school id). */
    val usernameClaim: String = "sub",
    val displayNameClaim: String = "name",
    val emailClaim: String = "email"
)

/**
 * Static configuration for a CAS identity provider.
 */
data class CasProviderConfig(
    /** CAS server base, e.g. https://cas.school.edu.cn/cas */
    val serverUrl: String,
    /** Attribute returned by CAS to use as the stable external id, null = use the CAS user id. */
    val principalAttribute: String? = null,
    val displayNameAttribute: String? = "displayName",
    val emailAttribute: String? = "mail"
)
