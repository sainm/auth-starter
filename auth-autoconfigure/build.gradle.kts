plugins {
    kotlin("jvm")
    kotlin("plugin.spring")
}

dependencies {
    api(project(":auth-core"))
    implementation(project(":auth-security"))
    implementation(project(":auth-audit"))
    implementation(project(":auth-persistence"))
    implementation(project(":auth-qr"))
    implementation(project(":auth-social-google"))
    implementation(project(":auth-social-wechat"))
    implementation("org.springframework.boot:spring-boot-autoconfigure")
    implementation("org.springframework.boot:spring-boot-configuration-processor")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.security:spring-security-crypto")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    testImplementation(kotlin("test"))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.h2database:h2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
