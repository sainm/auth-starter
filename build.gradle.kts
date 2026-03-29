plugins {
    kotlin("jvm") version "2.1.0" apply false
    kotlin("plugin.spring") version "2.1.0" apply false
    id("org.springframework.boot") version "3.4.0" apply false
    id("io.spring.dependency-management") version "1.1.6" apply false
}

allprojects {
    group = "org.sainm"
    version = "0.1.0-SNAPSHOT"

    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "io.spring.dependency-management")

    extensions.configure<io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension> {
        imports {
            mavenBom("org.springframework.boot:spring-boot-dependencies:3.4.0")
        }
        generatedPomCustomization {
            enabled(false)
        }
    }

    extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
        jvmToolchain(21)
    }

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.release.set(21)
    }

    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
            freeCompilerArgs.add("-Xjsr305=strict")
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
}

subprojects
    .filter { it.name != "auth-demo" }
    .forEach { project ->
        project.apply(plugin = "maven-publish")

        project.extensions.configure<JavaPluginExtension> {
            withSourcesJar()
            withJavadocJar()
        }

        project.afterEvaluate {
            extensions.configure<PublishingExtension> {
                publications {
                    create<MavenPublication>("mavenJava") {
                        artifactId = project.name
                        artifact(tasks.named("jar"))
                        artifact(tasks.named("sourcesJar"))
                        artifact(tasks.named("javadocJar"))
                        pom {
                            name.set(project.name)
                            description.set(
                                when (project.name) {
                                    "auth-core" -> "Core auth domain models and SPI contracts"
                                    "auth-security" -> "Spring Security and JWT support for auth-starter"
                                    "auth-persistence" -> "JDBC persistence defaults for auth-starter"
                                    "auth-qr" -> "QR login module for auth-starter"
                                    "auth-social-google" -> "Google social login module for auth-starter"
                                    "auth-social-wechat" -> "WeChat social login module for auth-starter"
                                    "auth-audit" -> "Audit publishing module for auth-starter"
                                    "auth-autoconfigure" -> "Spring Boot auto-configuration for auth-starter"
                                    "auth-spring-boot-starter" -> "Aggregate Spring Boot starter for auth-starter"
                                    else -> "Module ${project.name} for auth-starter"
                                }
                            )
                            url.set(findProperty("projectUrl") as String? ?: "https://example.com/org/sainm/auth-starter")
                            licenses {
                                license {
                                    name.set(findProperty("licenseName") as String? ?: "Apache License 2.0")
                                    url.set(findProperty("licenseUrl") as String? ?: "https://www.apache.org/licenses/LICENSE-2.0.txt")
                                }
                            }
                            developers {
                                developer {
                                    id.set(findProperty("developerId") as String? ?: "sainm")
                                    name.set(findProperty("developerName") as String? ?: "sainm")
                                    email.set(findProperty("developerEmail") as String? ?: "dev@example.com")
                                }
                            }
                            scm {
                                connection.set(findProperty("scmConnection") as String? ?: "scm:git:https://example.com/org/sainm/auth-starter.git")
                                developerConnection.set(findProperty("scmDeveloperConnection") as String? ?: "scm:git:ssh://git@example.com/org/sainm/auth-starter.git")
                                url.set(findProperty("scmUrl") as String? ?: "https://example.com/org/sainm/auth-starter")
                            }
                            withXml {
                                val dependenciesNode = asNode().appendNode("dependencies")
                                val seen = mutableSetOf<String>()

                                fun appendDependency(configurationName: String, scope: String) {
                                    project.configurations.findByName(configurationName)
                                        ?.allDependencies
                                        ?.forEach { dependency ->
                                            val coordinates = when (dependency) {
                                                is ProjectDependency -> {
                                                    val target = project.rootProject.findProject(dependency.path) ?: return@forEach
                                                    Triple(target.group.toString(), target.name, target.version.toString())
                                                }
                                                else -> {
                                                    val group = dependency.group ?: return@forEach
                                                    val version = dependency.version ?: return@forEach
                                                    Triple(group, dependency.name, version)
                                                }
                                            }

                                            val dependencyKey = "${coordinates.first}:${coordinates.second}:${coordinates.third}:$scope"
                                            if (!seen.add(dependencyKey)) {
                                                return@forEach
                                            }

                                            val dependencyNode = dependenciesNode.appendNode("dependency")
                                            dependencyNode.appendNode("groupId", coordinates.first)
                                            dependencyNode.appendNode("artifactId", coordinates.second)
                                            dependencyNode.appendNode("version", coordinates.third)
                                            dependencyNode.appendNode("scope", scope)
                                        }
                                }

                                appendDependency("api", "compile")
                                appendDependency("implementation", "runtime")
                                appendDependency("runtimeOnly", "runtime")
                            }
                        }
                    }
                }
                repositories {
                    val publishUrl = findProperty("publishRepoUrl") as String?
                    if (!publishUrl.isNullOrBlank()) {
                        maven {
                            name = "projectRepo"
                            url = uri(publishUrl)
                            credentials {
                                username = findProperty("publishRepoUsername") as String?
                                password = findProperty("publishRepoPassword") as String?
                            }
                        }
                    }
                }
            }
        }
    }
