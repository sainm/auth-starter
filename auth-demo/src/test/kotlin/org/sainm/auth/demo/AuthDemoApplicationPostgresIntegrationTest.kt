package org.sainm.auth.demo

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.TestPropertySource
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(
    properties = [
        "spring.datasource.driver-class-name=org.postgresql.Driver",
        "spring.sql.init.mode=always",
        "spring.sql.init.schema-locations=classpath:schema.sql",
        "spring.sql.init.data-locations=classpath:data.sql"
    ]
)
class AuthDemoApplicationPostgresIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @Test
    fun `password login works against postgresql container`() {
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
    }

    private fun readJson(raw: String): JsonNode = objectMapper.readTree(raw)

    companion object {
        @Container
        @JvmStatic
        val postgres: PostgreSQLContainer<*> = PostgreSQLContainer("postgres:16-alpine")
            .withDatabaseName("auth_demo_test")
            .withUsername("auth_demo")
            .withPassword("AuthDemo@Test")

        @JvmStatic
        @DynamicPropertySource
        fun registerPostgresProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url", postgres::getJdbcUrl)
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
        }
    }
}
