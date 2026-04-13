# Release Guide

## Versioning

- Use `0.x.y` while the starter API is still evolving.
- Bump `x` for breaking API or schema changes.
- Bump `y` for backward-compatible features and fixes.

## Pre-release Checklist

1. Run:
   `.\gradlew.bat --no-daemon clean build`
2. Verify [`README.md`](/d:/source/auth-starter/README.md), [`doc/api.md`](/d:/source/auth-starter/doc/api.md), and [`doc/schema-postgresql.sql`](/d:/source/auth-starter/doc/schema-postgresql.sql) match the code.
3. Run [`auth-demo`](/d:/source/auth-starter/auth-demo/build.gradle.kts) integration tests.
   The PostgreSQL Testcontainers test will auto-skip when Docker is unavailable.
4. Replace placeholder metadata in [`gradle.properties`](/d:/source/auth-starter/gradle.properties) with real SCM and developer values.
5. Record schema changes and behavior changes in [`CHANGELOG.md`](/d:/source/auth-starter/CHANGELOG.md).

## Local Publish Verification

`publishToMavenLocal` has been verified on the current repository by publishing explicit `jar`, `sourcesJar`, and `javadocJar` artifacts with a manually generated dependency section in the POM. Use the checked-in Gradle wrapper for local verification.

## Artifact Flow

Current publishable modules:

- `auth-core`
- `auth-security`
- `auth-persistence`
- `auth-qr`
- `auth-social-google`
- `auth-social-wechat`
- `auth-audit`
- `auth-autoconfigure`
- `auth-spring-boot-starter`

Recommended first publish target:

- internal Maven repository or Nexus/Artifactory

Recommended later publish target:

- Maven Central after metadata, signing, and stable coordinates are finalized

## Suggested Publish Steps

1. Update `version` in [`build.gradle.kts`](/d:/source/auth-starter/build.gradle.kts).
2. Run full verification.
3. Publish starter modules to the chosen repository.
4. Tag the release in git with `v<version>`.
5. Copy noteworthy changes into the changelog.
