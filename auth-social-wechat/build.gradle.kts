plugins {
    kotlin("jvm")
}

dependencies {
    api(project(":auth-core"))
    implementation("com.fasterxml.jackson.core:jackson-databind")
}
