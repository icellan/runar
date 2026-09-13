plugins {
    java
    application
}

group = "build.runar"
version = "1.0.0-rc.1"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

// Lock all configurations so the resolved dependency graph is committed as
// gradle.lockfile. The Dependency Audit CI workflow scans that lockfile with
// osv-scanner; regenerate with `gradle dependencies --write-locks` whenever
// a dependency version changes.
dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    // Placeholder deps. Populated in milestone 3 (parse/validate/typecheck).
    // implementation("com.github.javaparser:javaparser-core:3.25.10")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "runar.compiler.Cli"
    applicationName = "runar-java"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.named<Jar>("jar") {
    manifest {
        attributes(
            "Main-Class" to "runar.compiler.Cli",
            "Implementation-Title" to "Rúnar Java Compiler",
            "Implementation-Version" to project.version,
            // R-276: the jar travelled with no license metadata, while every
            // other ecosystem in this repo declares MIT in its own manifest
            // (package.json, Cargo.toml, the gemspec, pyproject). A jar without
            // it is the one artifact a consumer's license scanner cannot
            // classify. Bundle-License is the OSGi spelling scanners read;
            // Implementation-License is the plain one a human reads.
            "Implementation-License" to "MIT",
            "Bundle-License" to "https://opensource.org/licenses/MIT",
        )
    }
}
