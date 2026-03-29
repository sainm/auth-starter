package org.sainm.auth.security.api

data class ApiResponse<T>(
    val code: String,
    val message: String,
    val data: T?
) {
    companion object {
        fun <T> ok(data: T): ApiResponse<T> = ApiResponse("0", "OK", data)
    }
}
