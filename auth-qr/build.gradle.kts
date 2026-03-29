plugins {
    kotlin("jvm")
}

dependencies {
    api(project(":auth-core"))
    implementation("org.springframework:spring-jdbc")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("com.h2database:h2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
