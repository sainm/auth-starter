package org.sainm.auth.security.service

import org.sainm.auth.core.spi.SsoState
import org.sainm.auth.core.spi.SsoStateStore
import java.util.concurrent.ConcurrentHashMap

/**
 * Default in-memory [SsoStateStore]. Suitable for single-instance deployments
 * and tests. For multi-instance production, override this bean with a
 * distributed (e.g. Redis) implementation.
 */
class InMemorySsoStateStore(
    private val nowEpochSecond: () -> Long = { System.currentTimeMillis() / 1000 }
) : SsoStateStore {

    private data class Entry(val state: SsoState, val expiresAtEpochSecond: Long)

    private val store = ConcurrentHashMap<String, Entry>()

    override fun save(state: SsoState, ttlSeconds: Long) {
        purgeExpired()
        store[state.stateKey] = Entry(state, nowEpochSecond() + ttlSeconds)
    }

    override fun consume(stateKey: String): SsoState? {
        purgeExpired()
        val entry = store.remove(stateKey) ?: return null
        return if (entry.expiresAtEpochSecond >= nowEpochSecond()) entry.state else null
    }

    private fun purgeExpired() {
        val now = nowEpochSecond()
        store.entries.removeIf { it.value.expiresAtEpochSecond < now }
    }
}
