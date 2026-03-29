package org.sainm.auth.security.web

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.sainm.auth.core.spi.TokenService
import org.sainm.auth.security.context.TenantContextHolder
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter

class JwtAuthenticationFilter(
    private val tokenService: TokenService
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            val header = request.getHeader(HttpHeaders.AUTHORIZATION)
            if (header?.startsWith("Bearer ") == true) {
                val token = header.removePrefix("Bearer ").trim()
                val parsed = kotlin.runCatching {
                    val principal = tokenService.parse(token)
                    val authorities = principal.roles.map { SimpleGrantedAuthority("ROLE_$it") }
                    val authentication = UsernamePasswordAuthenticationToken(principal.userId, principal, authorities)
                    SecurityContextHolder.getContext().authentication = authentication
                    TenantContextHolder.setTenantId(principal.tenantId)
                }
                if (parsed.isFailure) {
                    SecurityContextHolder.clearContext()
                    TenantContextHolder.clear()
                }
            }
            filterChain.doFilter(request, response)
        } finally {
            TenantContextHolder.clear()
        }
    }
}
