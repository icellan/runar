plugins {
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
}

application {
    mainClass.set("runar.anfdriver.Driver")
}

// Produce a fat jar so the runner can invoke `java -jar` without
// fiddling with the classpath. Mirrors the SDK-output Java driver's
// single-binary release artifact.
tasks.register<Jar>("fatJar") {
    archiveBaseName.set("runar-anf-driver")
    archiveClassifier.set("")
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "runar.anfdriver.Driver"
    }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith(".jar") }
            .map { zipTree(it) }
    })
    // BouncyCastle jars ship signed. Strip signature files so the JVM
    // doesn't reject the shaded jar with SecurityException at startup.
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC")
}

tasks.named("build") {
    dependsOn("fatJar")
}
