package org.sainm.auth.demo

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication(scanBasePackages = ["org.sainm"])
class AuthDemoApplication

fun main(args: Array<String>) {
    runApplication<AuthDemoApplication>(*args)
}
