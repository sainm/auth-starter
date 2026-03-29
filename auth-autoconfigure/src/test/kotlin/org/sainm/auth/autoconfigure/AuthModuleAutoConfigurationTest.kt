package org.sainm.auth.autoconfigure

import org.sainm.auth.core.spi.QrLoginService
import org.sainm.auth.core.spi.SocialAuthProvider
import org.sainm.auth.core.spi.SocialLoginService
import org.sainm.auth.security.service.DefaultSocialLoginService
import org.sainm.auth.social.google.GoogleIdTokenSocialAuthProvider
import org.sainm.auth.social.google.MockGoogleSocialAuthProvider
import org.sainm.auth.social.wechat.MockWechatSocialAuthProvider
import org.sainm.auth.social.wechat.WechatCodeSocialAuthProvider
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration
import org.springframework.boot.test.context.runner.WebApplicationContextRunner
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class AuthModuleAutoConfigurationTest {

    private val contextRunner = WebApplicationContextRunner()
        .withConfiguration(
            AutoConfigurations.of(
                SecurityAutoConfiguration::class.java,
                WebMvcAutoConfiguration::class.java,
                DataSourceAutoConfiguration::class.java,
                JdbcTemplateAutoConfiguration::class.java,
                JacksonAutoConfiguration::class.java,
                AuthModuleAutoConfiguration::class.java
            )
        )
        .withPropertyValues(
            "spring.datasource.url=jdbc:h2:mem:auto_config_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
            "spring.datasource.driver-class-name=org.h2.Driver",
            "spring.datasource.username=sa",
            "spring.datasource.password="
        )

    @Test
    fun `qr bean is absent when qr login disabled`() {
        contextRunner
            .withPropertyValues("auth-module.qr-login.enabled=false")
            .run { context ->
                assertFalse(context.containsBean("jdbcQrLoginService"))
                assertFalse(context.getBeansOfType(QrLoginService::class.java).isNotEmpty())
            }
    }

    @Test
    fun `social providers are filtered by enabled types`() {
        contextRunner
            .withPropertyValues("auth-module.authentication.enabled-types=PASSWORD,WECHAT")
            .run { context ->
                val service = context.getBean(SocialLoginService::class.java) as DefaultSocialLoginService
                assertFailsWith<IllegalArgumentException> {
                    service.authenticate("GOOGLE", "code")
                }
                assertTrue(context.getBeansOfType(SocialLoginService::class.java).isNotEmpty())
            }
    }

    @Test
    fun `google provider falls back to mock when real config absent`() {
        contextRunner.run { context ->
            val provider = context.getBean("googleSocialAuthProvider", SocialAuthProvider::class.java)
            assertIs<MockGoogleSocialAuthProvider>(provider)
        }
    }

    @Test
    fun `google provider uses id token verifier when enabled with client id`() {
        contextRunner
            .withPropertyValues(
                "auth-module.social.google.enabled=true",
                "auth-module.social.google.client-id=test-client-id.apps.googleusercontent.com"
            )
            .run { context ->
                val provider = context.getBean("googleSocialAuthProvider", SocialAuthProvider::class.java)
                assertIs<GoogleIdTokenSocialAuthProvider>(provider)
            }
    }

    @Test
    fun `wechat provider falls back to mock when real config absent`() {
        contextRunner.run { context ->
            val provider = context.getBean("wechatSocialAuthProvider", SocialAuthProvider::class.java)
            assertIs<MockWechatSocialAuthProvider>(provider)
        }
    }

    @Test
    fun `wechat provider uses code exchange when enabled with app credentials`() {
        contextRunner
            .withPropertyValues(
                "auth-module.social.wechat.enabled=true",
                "auth-module.social.wechat.app-id=test-app-id",
                "auth-module.social.wechat.app-secret=test-app-secret"
            )
            .run { context ->
                val provider = context.getBean("wechatSocialAuthProvider", SocialAuthProvider::class.java)
                assertIs<WechatCodeSocialAuthProvider>(provider)
            }
    }
}
