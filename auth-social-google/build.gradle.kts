plugins {
    kotlin("jvm")
}

dependencies {
    api(project(":auth-core"))
    implementation("com.google.api-client:google-api-client:2.7.0")
    implementation("com.google.oauth-client:google-oauth-client:1.36.0")
    implementation("com.google.http-client:google-http-client-gson:1.45.0")
}
