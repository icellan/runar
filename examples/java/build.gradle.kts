plugins {
    java
}

group = "build.runar.examples"
version = "1.0.0-rc.1"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

// Contract source files use the .runar.java extension to signal they are
// Rúnar contracts, not generic Java. Wire them into the `main` source set
// alongside conventional .java files so `gradle build` compiles them against
// the runar-java SDK.
sourceSets {
    main {
        java {
            include("**/*.java")
            include("**/*.runar.java")
        }
    }
}

// R-210: lock the dependency graph so `osv-scanner` in dependency-audit.yml can
// see it. Five of the seven Gradle projects in this repo had no lock state, so
// the audit job scanned two lockfiles and the CI comment described the repo as
// having exactly those two. With lock state present, Gradle fails any ordinary
// build if a declared version changes without `gradle dependencies
// --write-locks`, so the scanned lockfile cannot drift from the real graph.
dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation("build.runar:runar-java:1.0.0-rc.1")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
