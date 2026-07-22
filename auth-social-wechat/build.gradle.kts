plugins {
    kotlin("jvm")
}

dependencies {
    api(project(":auth-core"))
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("org.slf4j:slf4j-api")
}
