plugins {
    kotlin("jvm")
    kotlin("plugin.spring")
}

dependencies {
    api(project(":auth-core"))
    implementation("org.springframework:spring-jdbc")
    implementation("org.springframework.security:spring-security-crypto")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("com.h2database:h2")
    testImplementation("org.springframework:spring-jdbc")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
