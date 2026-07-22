plugins {
    kotlin("jvm")
}

dependencies {
    api(project(":auth-core"))
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("org.springframework.security:spring-security-oauth2-jose")
    testImplementation(kotlin("test"))
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
