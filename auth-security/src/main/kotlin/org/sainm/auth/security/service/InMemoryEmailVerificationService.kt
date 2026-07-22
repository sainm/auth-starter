package org.sainm.auth.security.service

import org.sainm.auth.core.spi.EmailVerificationClaim
import org.sainm.auth.core.spi.EmailVerificationService
import java.util.concurrent.ConcurrentHashMap

/**
 * Default in-memory [EmailVerificationService]. Single-use tokens; consumed on
 * first valid call. For production with multiple nodes, replace with Redis.
 */
class InMemoryEmailVerificationService(
    private val nowEpochSecond: () -> Long = { System.currentTimeMillis() / 1000 }
) : EmailVerificationService {

    private data class Entry(
        val claim: EmailVerificationClaim,
        val expiresAtEpochSecond: Long
    )

    private val store = ConcurrentHashMap<String, Entry>()

    override fun generate(userId: Long, email: String, ttlSeconds: Long): String {
        purgeExpired()
        val token = java.util.UUID.randomUUID().toString().replace("-", "")
        store[token] = Entry(
            claim = EmailVerificationClaim(
                userId = userId,
                email = email,
                createdAtEpochSecond = nowEpochSecond()
            ),
            expiresAtEpochSecond = nowEpochSecond() + ttlSeconds
        )
        return token
    }

    override fun consume(token: String): EmailVerificationClaim? {
        purgeExpired()
        val entry = store.remove(token) ?: return null
        return if (entry.expiresAtEpochSecond >= nowEpochSecond()) entry.claim else null
    }

    private fun purgeExpired() {
        val now = nowEpochSecond()
        store.entries.removeIf { it.value.expiresAtEpochSecond < now }
    }
}
