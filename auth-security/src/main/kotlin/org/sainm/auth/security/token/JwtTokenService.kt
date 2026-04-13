package org.sainm.auth.security.token

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.sainm.auth.core.domain.TokenPair
import org.sainm.auth.core.domain.UserPrincipal
import org.sainm.auth.core.domain.UserStatus
import org.sainm.auth.core.exception.InvalidTokenException
import org.sainm.auth.core.spi.TokenBlacklistService
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.core.spi.UserLookupService
import java.time.Clock
import java.time.Instant
import java.util.Date
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class JwtTokenService(
    private val properties: JwtTokenProperties,
    private val tokenBlacklistService: TokenBlacklistService? = null,
    private val userLookupService: UserLookupService? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val passwordVersionCacheTtlSeconds: Long = 30
) : TokenService {

    private val passwordVersionCache = ConcurrentHashMap<Long, CachedPasswordVersion>()

    override fun generate(userPrincipal: UserPrincipal): TokenPair {
        val now = Instant.now(clock)
        val accessExpiresAt = now.plusSeconds(properties.accessTokenExpireMinutes * 60)
        val refreshExpiresAt = now.plusSeconds(properties.refreshTokenExpireDays * 24 * 60 * 60)
        return TokenPair(
            accessToken = createToken(userPrincipal, now, accessExpiresAt, "access"),
            refreshToken = createToken(userPrincipal, now, refreshExpiresAt, "refresh"),
            expiresIn = properties.accessTokenExpireMinutes * 60
        )
    }

    override fun parse(accessToken: String): UserPrincipal {
        val claims = parseClaims(accessToken)
        return claims.toUserPrincipal()
    }

    override fun refresh(refreshToken: String): TokenPair {
        val claims = parseClaims(refreshToken)
        if (claims.getStringClaim("tokenUse") != "refresh") {
            throw InvalidTokenException("auth.refreshToken.invalid")
        }
        val tokenPair = generate(claims.toUserPrincipal())
        invalidate(refreshToken)
        return tokenPair
    }

    override fun invalidate(accessToken: String) {
        val claims = parseVerifiedClaims(accessToken)
        val jti = claims.jwtid ?: return
        val userId = claims.subject?.toLongOrNull() ?: return
        val expireAt = claims.expirationTime?.toInstant()?.epochSecond ?: return
        tokenBlacklistService?.blacklist(jti, userId, expireAt)
    }

    private fun JWTClaimsSet.toUserPrincipal(): UserPrincipal =
        UserPrincipal(
            userId = subject.toLong(),
            username = getStringClaim("username"),
            displayName = getStringClaim("displayName"),
            status = UserStatus.valueOf(getStringClaim("status")),
            groupId = getLongClaimSafely("groupId"),
            tenantId = getLongClaimSafely("tenantId"),
            roles = getStringListClaim("roles")?.toSet().orEmpty(),
            permissions = getStringListClaim("permissions")?.toSet().orEmpty(),
            attributes = mapOf("passwordVersion" to getIntegerClaim("passwordVersion"))
        )

    private fun createToken(
        principal: UserPrincipal,
        issuedAt: Instant,
        expiresAt: Instant,
        tokenUse: String
    ): String {
        val claims = JWTClaimsSet.Builder()
            .jwtID(UUID.randomUUID().toString())
            .issuer(properties.issuer)
            .issueTime(Date.from(issuedAt))
            .expirationTime(Date.from(expiresAt))
            .subject(principal.userId.toString())
            .claim("username", principal.username)
            .claim("displayName", principal.displayName)
            .claim("status", principal.status.name)
            .claim("groupId", principal.groupId)
            .claim("tenantId", principal.tenantId)
            .claim("roles", principal.roles.toList())
            .claim("permissions", principal.permissions.toList())
            .claim("tokenUse", tokenUse)
            .claim("passwordVersion", (principal.attributes["passwordVersion"] as? Number)?.toInt() ?: 1)
            .build()

        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build(),
            claims
        )
        try {
            jwt.sign(MACSigner(properties.secret.toByteArray()))
        } catch (ex: JOSEException) {
            throw IllegalStateException("Failed to sign JWT", ex)
        }
        return jwt.serialize()
    }

    private fun parseClaims(token: String): JWTClaimsSet {
        val claims = parseVerifiedClaims(token)
        val jti = claims.jwtid
        if (jti != null && tokenBlacklistService?.isBlacklisted(jti) == true) {
            throw InvalidTokenException()
        }
        validatePasswordVersion(claims)
        return claims
    }

    private fun parseVerifiedClaims(token: String): JWTClaimsSet {
        val jwt = SignedJWT.parse(token)
        if (!jwt.verify(MACVerifier(properties.secret.toByteArray()))) {
            throw InvalidTokenException("auth.token.signature.invalid")
        }
        return jwt.jwtClaimsSet
    }

    private fun validatePasswordVersion(claims: JWTClaimsSet) {
        val userId = claims.subject?.toLongOrNull() ?: return
        val tokenPasswordVersion = claims.getIntegerClaim("passwordVersion") ?: 1
        val currentPasswordVersion = currentPasswordVersion(userId) ?: tokenPasswordVersion
        if (currentPasswordVersion > tokenPasswordVersion) {
            throw InvalidTokenException("auth.token.passwordVersion.invalid")
        }
    }

    private fun currentPasswordVersion(userId: Long): Int? {
        val now = Instant.now(clock).epochSecond
        val cached = passwordVersionCache[userId]
        if (cached != null && cached.expiresAtEpochSecond > now) {
            return cached.version
        }

        val version = userLookupService
            ?.findById(userId)
            ?.attributes
            ?.get("passwordVersion")
            ?.let { it as? Number }
            ?.toInt()
            ?: return null

        passwordVersionCache[userId] = CachedPasswordVersion(
            version = version,
            expiresAtEpochSecond = now + passwordVersionCacheTtlSeconds.coerceAtLeast(1)
        )
        return version
    }
}

data class JwtTokenProperties(
    val secret: String,
    val issuer: String,
    val accessTokenExpireMinutes: Long,
    val refreshTokenExpireDays: Long
)

private data class CachedPasswordVersion(
    val version: Int,
    val expiresAtEpochSecond: Long
)

private fun JWTClaimsSet.getLongClaimSafely(name: String): Long? =
    getClaim(name)?.let { (it as Number).toLong() }
