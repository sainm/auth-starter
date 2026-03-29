package org.sainm.auth.demo

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@SpringBootTest
@AutoConfigureMockMvc
class AuthDemoApplicationIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @Test
    fun `password login and authenticated queries work in demo app`() {
        val loginResponse = mockMvc.perform(
            post("/auth/login/password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "principal": "admin",
                      "password": "P@ssw0rd!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isOk)
            .andReturn()
            .response
            .contentAsString

        val loginJson = objectMapper.readTree(loginResponse)
        val accessToken = loginJson.required("data").required("accessToken").asText()
        assertTrue(accessToken.isNotBlank())

        val meJson = readJson(
            mockMvc.perform(
                get("/auth/me")
                    .header("Authorization", "Bearer $accessToken")
            ).andExpect(status().isOk)
                .andReturn()
                .response
                .contentAsString
        )
        assertEquals("admin", meJson.required("data").required("username").asText())

        val usersJson = readJson(
            mockMvc.perform(
                get("/auth/users")
                    .header("Authorization", "Bearer $accessToken")
            ).andExpect(status().isOk)
                .andReturn()
                .response
                .contentAsString
        )
        assertTrue(usersJson.required("data").isArray)
        assertEquals("admin", usersJson.required("data")[0].required("username").asText())
    }

    private fun readJson(raw: String): JsonNode = objectMapper.readTree(raw)
}
