package org.sainm.auth.security.context

object TenantContextHolder {
    private val tenantIdHolder = ThreadLocal<Long?>()

    fun setTenantId(tenantId: Long?) {
        tenantIdHolder.set(tenantId)
    }

    fun getTenantId(): Long? = tenantIdHolder.get()

    fun clear() {
        tenantIdHolder.remove()
    }
}
