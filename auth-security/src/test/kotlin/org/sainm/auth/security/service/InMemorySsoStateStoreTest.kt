package org.sainm.auth.security.service

import org.sainm.auth.core.spi.SsoState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class InMemorySsoStateStoreTest {

    @Test
    fun `save then consume returns state within TTL`() {
        val store = InMemorySsoStateStore()
        val state = SsoState(
            stateKey = "key1",
            provider = "OIDC",
            nonce = "nonce123",
            redirectUri = "https://psy.school.edu.cn/auth/sso/oidc/callback",
            returnTo = "/dashboard"
        )
        store.save(state, ttlSeconds = 60)
        val result = store.consume("key1")
        assertEquals(state, result)
    }

    @Test
    fun `consume removes the state so second consume returns null`() {
        val store = InMemorySsoStateStore()
        store.save(SsoState("k2", "CAS"), ttlSeconds = 60)
        store.consume("k2")
        assertNull(store.consume("k2"))
    }

    @Test
    fun `consume returns null for unknown key`() {
        val store = InMemorySsoStateStore()
        assertNull(store.consume("nonexistent"))
    }

    @Test
    fun `expired entries are not returned`() {
        var now = 1_000L
        val store = InMemorySsoStateStore(nowEpochSecond = { now })
        store.save(SsoState("expired", "OIDC"), ttlSeconds = 5)
        now = 1_010L // advance 10s past TTL
        assertNull(store.consume("expired"))
    }

    @Test
    fun `entry at exactly TTL boundary is still accessible`() {
        var now = 1_000L
        val store = InMemorySsoStateStore(nowEpochSecond = { now })
        store.save(SsoState("border", "CAS"), ttlSeconds = 5)
        now = 1_005L // exactly at expiry — expiresAt == now, should still be valid
        val result = store.consume("border")
        assertEquals("border", result?.stateKey)
    }

    @Test
    fun `save overwrites existing key with new state`() {
        val store = InMemorySsoStateStore()
        store.save(SsoState("dup", "OIDC", nonce = "n1"), ttlSeconds = 60)
        store.save(SsoState("dup", "CAS", nonce = "n2"), ttlSeconds = 60)
        val result = store.consume("dup")
        assertEquals("CAS", result?.provider)
        assertEquals("n2", result?.nonce)
    }
}
